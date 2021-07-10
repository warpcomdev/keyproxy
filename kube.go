package main

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubeAPI struct {
	Logger         *log.Logger
	KubeconfigPath string
	Namespace      string
	client         *kubernetes.Clientset
}

// See https://github.com/kubernetes/kubernetes/pull/63707
// and https://stackoverflow.com/questions/55314152/how-to-get-namespace-from-current-context-set-in-kube-config/65661997#65661997
func (k *KubeAPI) getNamespace() string {
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

func NewAPI(logger *log.Logger, kubeconfigPath, namespace string) (*KubeAPI, error) {
	k := &KubeAPI{
		Logger:         logger,
		KubeconfigPath: kubeconfigPath,
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
	// Get namespace too
	k.client = clientset
	if namespace == "" {
		namespace = k.getNamespace()
	}
	k.Namespace = namespace
	return k, nil
}

type PodPhase string
type EventType string

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
)

type PodInfo struct {
	Type    EventType
	Phase   PodPhase
	Address string
}

// PodStatus gets the pod's current status and IP address
func (k *KubeAPI) PodStatus(ctx context.Context, name string) (PodInfo, error) {
	pod, err := k.client.CoreV1().Pods(k.Namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return PodInfo{Type: Deleted, Phase: PodUnknown}, nil
		}
		return PodInfo{Type: Error, Phase: PodUnknown}, err
	}
	return PodInfo{Type: Modified, Phase: PodPhase(pod.Status.Phase), Address: pod.Status.PodIP}, nil
}

// PodWatch subscribes to the pod's PodInfo events
func (k *KubeAPI) PodWatch(ctx context.Context, name string) (<-chan PodInfo, error) {
	opts := metav1.ListOptions{
		FieldSelector: fields.OneTermEqualSelector(metav1.ObjectNameField, name).String(),
	}
	stream, err := k.client.CoreV1().Pods(k.Namespace).Watch(ctx, opts)
	if err != nil {
		return nil, err
	}
	events := make(chan PodInfo, 16)
	// Delegates closing the stream and events to forwardEvents
	go k.forwardEvents(ctx, name, stream, events)
	return events, nil
}

func (k *KubeAPI) forwardEvents(ctx context.Context, name string, stream watch.Interface, events chan<- PodInfo) {
	defer close(events)
	loggerCtx := k.Logger.WithField("name", name)
	for {
		select {
		case <-ctx.Done():
			// Stop and exhaust the stream, to release the ssucription
			stream.Stop()
			for range stream.ResultChan() {
			}
			return
		case event, ok := <-stream.ResultChan():
			if !ok {
				// No more events to stream, return
				loggerCtx.Info("Watch input stream closed")
				return
			}
			pod, err := k.castPod(event.Object)
			if err != nil {
				loggerCtx.WithField("type", event.Type).WithError(err).Error("Failed to cast event as pod")
				continue
			}
			events <- PodInfo{
				Type:    EventType(event.Type),
				Phase:   PodPhase(pod.Status.Phase),
				Address: pod.Status.PodIP,
			}
		}
	}
}

func (k *KubeAPI) PodDelete(ctx context.Context, name string) error {
	err := k.client.CoreV1().Pods(k.Namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && kerrors.IsNotFound(err) {
		log.WithField("name", name).Info("Pod does not exist, skipping")
		return nil
	}
	return err
}

// Alias to avoid having to import the v1 apis in other files
type PodDescriptor = v1.Pod

func (k *KubeAPI) Decode(template string) (*PodDescriptor, error) {
	decoder := scheme.Codecs.UniversalDeserializer()
	obj, _, err := decoder.Decode([]byte(template), nil, nil)
	if err != nil {
		return nil, err
	}
	pod, err := k.castPod(obj)
	if err != nil {
		return nil, err
	}
	return pod, nil
}

func (k *KubeAPI) PodCreate(ctx context.Context, desc *PodDescriptor) error {
	pod, err := k.client.CoreV1().Pods(k.Namespace).Create(ctx, desc, metav1.CreateOptions{})
	if err != nil {
		if !kerrors.IsAlreadyExists(err) {
			return err
		}
		log.WithField("name", pod.Name).Info("Pod already exists, skipping")
	}
	return nil
}

func (k *KubeAPI) castPod(obj runtime.Object) (*v1.Pod, error) {
	gvk := obj.GetObjectKind().GroupVersionKind()
	if gvk.Kind != "" && gvk.Kind != "Pod" {
		return nil, errors.New(fmt.Sprintf("Object kind is not pod but %+v", gvk.Kind))
	}
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil, errors.New(fmt.Sprintf("Could not cast kind %+v to v1.Pod struct", gvk.Kind))
	}
	return pod, nil
}
