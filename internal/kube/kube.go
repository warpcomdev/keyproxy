package kube

import (
	"context"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/informers"
	informersv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"k8s.io/client-go/util/workqueue"
)

// PodPhase encapsulates kubernetes own PodPhase type
type PodPhase string

// EventType encapsulates kubernetes own EventType type
type EventType string

// PodDescriptor is an alias to avoid having to import the v1 apis in other files.
type PodDescriptor = v1.Pod

const (
	// PodPending means the pod has been accepted by the system, but one or more of the containers
	// has not been started. This includes time before being bound to a node, as well as time spent
	// pulling images onto the host.
	PodPending PodPhase = PodPhase(v1.PodPending)
	// PodRunning means the pod has been bound to a node and all of the containers have been started.
	// At least one container is still running or is in the process of being restarted.
	PodRunning PodPhase = PodPhase(v1.PodRunning)
	// PodSucceeded means that all containers in the pod have voluntarily terminated
	// with a container exit code of 0, and the system is not going to restart any of these containers.
	PodSucceeded PodPhase = PodPhase(v1.PodSucceeded)
	// PodFailed means that all containers in the pod have terminated, and at least one container has
	// terminated in a failure (exited with a non-zero exit code or was stopped by the system).
	PodFailed PodPhase = PodPhase(v1.PodFailed)
	// PodUnknown means that for some reason the state of the pod could not be obtained, typically due
	// to an error in communicating with the host of the pod.
	PodUnknown PodPhase = PodPhase(v1.PodUnknown)

	Added    EventType = EventType(watch.Added)
	Modified EventType = EventType(watch.Modified)
	Deleted  EventType = EventType(watch.Deleted)
	Bookmark EventType = EventType(watch.Bookmark)
	Error    EventType = EventType(watch.Error)

	// Maximum number of retries por handler
	MaxRetries = 3
)

// PodInfo encapsulates the pod information delivered.
type PodInfo struct {
	Name    string
	Type    EventType
	Phase   PodPhase
	Address string
	Ready   bool
}

// EventHandler manages events
type EventHandler interface {
	Update(info PodInfo) error
}

// PodKindError raised when received event for an object which is not a pod.
type PodKindError string

func (err PodKindError) Error() string {
	return string(err)
}

var CacheSyncError = errors.New("Failed to synchronize cache")

// API encapsulates calls to Kubernetes API
type API struct {
	Logger         *log.Logger
	KubeconfigPath string
	Namespace      string
	client         *kubernetes.Clientset
	podInformer    informersv1.PodInformer
	queue          workqueue.RateLimitingInterface
	waitGroup      sync.WaitGroup
	cancelFunc     func()
}

// Loop tries to build API by autodiscovering cluster and namespace
func Loop(logger *log.Logger, namespace string, handler EventHandler, threads int, labels map[string]string) (*API, error) {
	k := &API{
		Logger:         logger,
		KubeconfigPath: filepath.Join(homedir.HomeDir(), ".kube", "config"),
	}
	config, err := rest.InClusterConfig()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			return nil, err
		}
		config, err = clientcmd.BuildConfigFromFlags("", k.KubeconfigPath)
		if err != nil {
			return nil, err
		}
	}
	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	k.client = clientset
	// Get namespace too
	if namespace == "" {
		namespace = k.namespace()
	}
	k.Namespace = namespace
	// Build informer, filtering pods by provided labels
	selectorLabels := func(lo *metav1.ListOptions) {
		lo.LabelSelector = metav1.FormatLabelSelector(&metav1.LabelSelector{MatchLabels: labels})
	}
	informerFactory := informers.NewSharedInformerFactoryWithOptions(clientset,
		time.Minute*30,
		informers.WithTweakListOptions(selectorLabels),
		informers.WithNamespace(k.Namespace))
	k.podInformer = informerFactory.Core().V1().Pods()
	// Start informerFactory and wait for sync
	logger.Info("Starting informer factory and waiting for cache sync")
	cancelCtx, cancelFunc := context.WithCancel(context.Background())
	k.cancelFunc = cancelFunc
	informerFactory.Start(cancelCtx.Done())
	for _, ok := range informerFactory.WaitForCacheSync(cancelCtx.Done()) {
		if !ok {
			return nil, CacheSyncError
		}
	}
	// Create queue and workers
	logger.Info("Starting controller threads")
	k.queue = workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	for i := 0; i < threads; i++ {
		k.waitGroup.Add(1)
		go k.dequeue(handler)
	}
	// Start informer
	logger.Info("Starting informer.Run")
	k.waitGroup.Add(1)
	go k.enqueue(cancelCtx)
	return k, nil
}

// Cancel the factory and listeners
func (k *API) Cancel() {
	if k.cancelFunc != nil {
		k.cancelFunc() // this will stop the informerFactory and informer
		k.cancelFunc = nil
	}
	k.queue.ShutDown()
	k.waitGroup.Wait()
}

// See https://github.com/kubernetes/kubernetes/pull/63707
// and https://stackoverflow.com/questions/55314152/how-to-get-namespace-from-current-context-set-in-kube-config/65661997#65661997
func (k *API) namespace() string {
	// This way assumes you've set the POD_NAMESPACE environment variable using the downward API.
	// This check has to be done first for backwards compatibility with the way InClusterConfig was originally set up
	if ns, ok := os.LookupEnv("POD_NAMESPACE"); ok {
		return ns
	}
	// Fall back to the namespace associated with the service account token, if available
	if data, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if ns := strings.TrimSpace(string(data)); len(ns) > 0 {
			return ns
		}
	}
	if clientCfg, err := clientcmd.NewDefaultClientConfigLoadingRules().Load(); err == nil {
		return clientCfg.Contexts[clientCfg.CurrentContext].Namespace
	}
	return "default"
}

// PodStatus gets the pod's current status and IP address
func (k *API) PodStatus(name string) (PodInfo, error) {
	pod, err := k.podInformer.Lister().Pods(k.Namespace).Get(name)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return PodInfo{Name: name, Type: Deleted, Phase: PodUnknown, Ready: false}, nil
		}
		return PodInfo{Name: name, Type: Error, Phase: PodUnknown, Ready: false}, err
	}
	ready := false
	if pod.Status.ContainerStatuses != nil {
		ready = true
		for _, status := range pod.Status.ContainerStatuses {
			if !status.Ready {
				ready = false
				break
			}
		}
	}
	return PodInfo{Name: name, Type: Modified, Phase: PodPhase(pod.Status.Phase), Address: pod.Status.PodIP, Ready: ready}, nil
}

// Enqueue informer events to work queue
func (k *API) enqueue(ctx context.Context) {
	defer k.waitGroup.Done()
	defer utilruntime.HandleCrash()
	logger := k.Logger
	logger.Info("Starting pod watch")
	k.podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			k.onUpdate(cache.MetaNamespaceKeyFunc(obj))
		},
		UpdateFunc: func(old, new interface{}) {
			k.onUpdate(cache.MetaNamespaceKeyFunc(new))
		},
		DeleteFunc: func(obj interface{}) {
			k.onUpdate(cache.DeletionHandlingMetaNamespaceKeyFunc(obj))
		},
	})
	k.podInformer.Informer().Run(ctx.Done())
	logger.Info("Exiting pod watch")
}

// onUpdate queues the key if err is nil
func (k *API) onUpdate(key string, err error) {
	if err != nil {
		k.Logger.WithError(err).Error("Failed to decode received obj")
		return
	}
	k.queue.Add(key)
}

// dequete work items
func (k *API) dequeue(handler EventHandler) {
	defer k.waitGroup.Done()
	defer utilruntime.HandleCrash()
	for k.forwardEvent(handler) {
	}
}

// forwardEvent manages the item
func (k *API) forwardEvent(handler EventHandler) bool {
	obj, shutdown := k.queue.Get()
	if shutdown {
		return false
	}
	defer k.queue.Done(obj)
	key, ok := obj.(string)
	if !ok {
		k.Logger.WithField("obj", obj).Error("Unexpected object in work queue")
		k.queue.Forget(obj)
		return true
	}
	logger := k.Logger.WithField("key", key)
	_, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		logger.WithError(err).Error("Failed to split key into namespace and name")
		k.queue.Forget(obj)
		return true
	}
	info, err := k.PodStatus(name)
	if err == nil {
		err = handler.Update(info)
	}
	switch {
	case err == nil:
		k.queue.Forget(obj)
		break
	case k.queue.NumRequeues(obj) >= MaxRetries:
		logger.WithError(err).Error("Max retries exceeded")
		k.queue.Forget(obj)
		break
	default:
		logger.WithError(err).Error("Failed to update, retrying")
		k.queue.AddRateLimited(obj)
		break
	}
	return true
}

// Decode reads the yaml descriptor for a pod
func (k *API) Decode(template string) (*PodDescriptor, error) {
	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode([]byte(template), nil, nil)
	if err != nil {
		return nil, err
	}
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil, PodKindError("Failed to decode template to pod")
	}
	return pod, nil
}

// DeletePod destroys pod by name
func (k *API) DeletePod(ctx context.Context, name string) error {
	err := k.client.CoreV1().Pods(k.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && kerrors.IsNotFound(err) {
		log.WithField("name", name).Info("Pod does not exist, skipping")
		return nil
	}
	return err
}

// CreatePod with given PodDescriptor
func (k *API) CreatePod(ctx context.Context, desc *PodDescriptor) error {
	pod, err := k.client.CoreV1().Pods(k.Namespace).Create(ctx, desc, metav1.CreateOptions{})
	if err != nil {
		if !kerrors.IsAlreadyExists(err) {
			return err
		}
		log.WithField("name", pod.Name).Info("Pod already exists, skipping")
	}
	return nil
}

// ServerVersion returns server version
func (k *API) ServerVersion() (*version.Info, error) {
	return k.client.ServerVersion()
}
