# Extending Kubernetes — Part 2 — Mutating Webhook

![enter image description here](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/extending_kubernetes_mutating_webhook.png?token=AA46XG5KJN3Q3R7DKQEMH4S7R3I7C)

Extending Kubernetes is a series of articles that explore different options available to extend the Kubernetes system's functionality. The series discusses some of the methods to extend the functionality of Kubernetes.

In this part 2 of the series, we will discuss how to develop a Mutating Webhook.

# Admission Controllers

Kubernetes Admission Controllers are component that intercepts API requests and can accept or reject the API requests. Admission controllers can modify, approve, or deny the incoming API requests. There are many admission controllers are there in the Kubernetes system. Two of them are of particular interest to us, the mutating webhook admission controller and the validating webhook admission controller.

# What are the admission webhooks?

Admission Webhooks are HTTP callbacks that Admission Controllers calls when there is an API request. Admission Webhook returns responses to the API Requests. There are two types of Admission Webhooks in Kubernetes, Mutating Admission Webhooks and Validating Admission Webhooks.

The Admission Controller calls mutating webhooks while in the mutating phase. Mutating Webhooks can modify the incoming objects. Mutating Webhooks can do it by sending a patch in the response. Examples of mutating webhooks are, adding additional labels and annotations, injecting sidecar containers, etc.

Validating Admission Webhooks called in the validating phase and can only accept or reject a request. It cannot modify the object. Examples of validating webhooks allow access to only authorized namespaces, allowing/denying the incoming API requests based on corporate policy, etc.

Here is a diagram representing the admission controller phases.

![Kubernetes API Request](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/Kubernetes%20API%20Request.jpeg?token=AA46XG2E5VY2MYRT7UNHKAC7R26GC)

In this article, we will explore mutating webhooks. In the next part, we will explore validating webhook.

I searched a lot on Google about the Mutating Webhooks; several resources explain how to create mutating webhooks. One particular example that I consider is this [sample code](https://github.com/kubernetes-sigs/controller-runtime/tree/master/examples/builtins). The sample is from the controller-runtime repository. I took the [mutatingwebhook.go](https://github.com/kubernetes-sigs/controller-runtime/blob/master/examples/builtins/mutatingwebhook.go) and [main.go](https://github.com/kubernetes-sigs/controller-runtime/blob/master/examples/builtins/main.go) as a starting point.

This article will create a webhook that inserts a sidecar container that handles the application logs. We all know the application log is an integral part of the application development. Many specialized tools are there that aggregate logs and send them for processing. We choose one tool and may decide to change it at a later stage. To make it easy to replace the logging tool at any stage, we usually write a wrapper around the logging module and hide all the log complexity. In this article, we will develop a simple module that handles application logs. We will expose an HTTP API that will accept a string and log to the console. In an actual implementation, we may use any production-grade tools like FluentBit, Open Telemetry, etc. However, for the sake of simplicity, we will print it to the console.

The mutating webhook that we will develop will automatically inject the logging server container into our Kubernetes application. It will enable the application developer to concentrate on the logic and connect to the logging module and log application events.

As explained earlier, the Admission Controller allows Mutating Webhook to modify the incoming API request. We can insert a container spec in the incoming API request. The API request will finally become a multi-container pod.

# Let's start coding

As I mentioned later, we will take the sample from the controller-runtime. Our main.go file looks like:

    package main  
      
    import (  
	     "crypto/sha256"  
	     "flag" 
	     "io/ioutil" 
	     "os" 
	     "path/filepath"  
	     "github.com/golang/glog"  
	     hook "github.com/krvarma/wh/webhook"  
	     "gopkg.in/yaml.v2"  
	     _ "k8s.io/client-go/plugin/pkg/client/auth/gcp"  
	     "sigs.k8s.io/controller-runtime/pkg/client/config"  
	     logf "sigs.k8s.io/controller-runtime/pkg/log"  
	     "sigs.k8s.io/controller-runtime/pkg/log/zap" 
	     "sigs.k8s.io/controller-runtime/pkg/manager" 
	     "sigs.k8s.io/controller-runtime/pkg/manager/signals"
	     "sigs.k8s.io/controller-runtime/pkg/webhook"
     )  
      
    var log = logf.Log.WithName("example-controller")  
      
    type HookParamters struct {  
       certDir string  
      sidecarConfig string  
      port int  
    }  
      
    func visit(files *[]string) filepath.WalkFunc {  
       return func(path string, info os.FileInfo, err error) error {  
          if err != nil {  
             return nil  
      }  
          *files = append(*files, path)  
          return nil  
      }  
    }  
      
    func loadConfig(configFile string) (*hook.Config, error) {  
       data, err := ioutil.ReadFile(configFile)  
       if err != nil {  
          return nil, err  
      }  
       glog.Infof("New configuration: sha256sum %x", sha256.Sum256(data))  
      
       var cfg hook.Config  
      if err := yaml.Unmarshal(data, &cfg); err != nil {  
          return nil, err  
      }  
      
       return &cfg, nil  
    }  
      
    func main() {  
       var params HookParamters  
      
      flag.IntVar(&params.port, "port", 8443, "Wehbook port")  
       flag.StringVar(&params.certDir, "certDir", "/certs/", "Wehbook certificate folder")  
       flag.StringVar(&params.sidecarConfig, "sidecarConfig", "/etc/webhook/config/sidecarconfig.yaml", "Wehbook sidecar config")  
       flag.Parse()  
      
       logf.SetLogger(zap.Logger(false))  
       entryLog := log.WithName("entrypoint")  
      
       // Setup a Manager  
      entryLog.Info("setting up manager")  
       mgr, err := manager.New(config.GetConfigOrDie(), manager.Options{})  
       if err != nil {  
          entryLog.Error(err, "unable to set up overall controller manager")  
          os.Exit(1)  
       }  
      
       config, err := loadConfig(params.sidecarConfig)  
      
       // Setup webhooks  
      entryLog.Info("setting up webhook server")  
       hookServer := mgr.GetWebhookServer()  
      
       hookServer.Port = params.port  
     hookServer.CertDir = params.certDir  
      
     entryLog.Info("registering webhooks to the webhook server")  
       hookServer.Register("/mutate", &webhook.Admission{Handler: &hook.SidecarInjector{Name: "Logger", Client: mgr.GetClient(), SidecarConfig: config}})  
      
       entryLog.Info("starting manager")  
       if err := mgr.Start(signals.SetupSignalHandler()); err != nil {  
          entryLog.Error(err, "unable to run manager")  
          os.Exit(1)  
       }  
    }

As you can see from the above code, we create a new Controller Manager using the manager.New() method. The method will return an instance of the controller manager. After that, we retrieve the Webhook server using GetWebhookServer() method. Once the Webhook server is retrieved, we should configure the Webhook server by setting the server port, certificate folder, etc. Then we register the API path with http.Handler. The Webhook.go file contains the handler function.

    package hook  
      
    import (  
       "context"
       "encoding/json" 
       "net/http" 
       "strconv"  
       "github.com/prometheus/common/log"  
       corev1 "k8s.io/api/core/v1"  
       "sigs.k8s.io/controller-runtime/pkg/client" 
       "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
    )  
      
    // +kubebuilder:webhook:path=/mutate,mutating=true,failurePolicy=fail,groups="",resources=pods,verbs=create;update,versions=v1,name=mpod.kb.io  
      
    // SidecarInjector annotates Pods
    type SidecarInjector struct {  
       Name string  
      Client client.Client  
      decoder *admission.Decoder  
      SidecarConfig *Config  
    }  
      
    type Config struct {  
       Containers []corev1.Container `yaml:"containers"`  
    }  
      
    func shoudInject(pod *corev1.Pod) bool {  
       shouldInjectSidecar, err := strconv.ParseBool(pod.Annotations["inject-logging-sidecar"])  
      
       if err != nil {  
          shouldInjectSidecar = false  
      }  
      
       if shouldInjectSidecar {  
          alreadyUpdated, err := strconv.ParseBool(pod.Annotations["logging-sidecar-added"])  
      
          if err == nil && alreadyUpdated {  
             shouldInjectSidecar = false  
      }  
       }  
      
       log.Info("Should Inject: ", shouldInjectSidecar)  
      
       return shouldInjectSidecar  
    }  
      
    // SidecarInjector adds an annotation to every incoming pods.func (si *SidecarInjector) Handle(ctx context.Context, req admission.Request) admission.Response {  
       pod := &corev1.Pod{}  
      
       err := si.decoder.Decode(req, pod)  
       if err != nil {  
          log.Info("Sdecar-Injector: cannot decode")  
          return admission.Errored(http.StatusBadRequest, err)  
       }  
      
       if pod.Annotations == nil {  
          pod.Annotations = map[string]string{}  
       }  
      
       shoudInjectSidecar := shoudInject(pod)  
      
       if shoudInjectSidecar {  
          log.Info("Injecting sidecar...")  
      
          pod.Spec.Containers = append(pod.Spec.Containers, si.SidecarConfig.Containers...)  
      
          pod.Annotations["logging-sidecar-added"] = "true"  
      
      log.Info("Sidecar ", si.Name, " injected.")  
       } else {  
          log.Info("Inject not needed.")  
       }  
      
       marshaledPod, err := json.Marshal(pod)  
      
       if err != nil {  
          log.Info("Sdecar-Injector: cannot marshal")  
          return admission.Errored(http.StatusInternalServerError, err)  
       }  
      
       return admission.PatchResponseFromRaw(req.Object.Raw, marshaledPod)  
    }  
      
    // SidecarInjector implements admission.DecoderInjector.  
    // A decoder will be automatically inj1ected.  
      
    // InjectDecoder injects the decoder.func (si *SidecarInjector) InjectDecoder(d *admission.Decoder) error {  
       si.decoder = d  
      return nil  
    }

The point of interest is the Handle function. This function handles the logic behind the sidecar injection. In this function, we check whether the incoming request has an annotation named _inject-logging-sidecar._ Our example webhook will not inject the sidecar if this annotation is not present or set to false. If this annotation is present and it true, we proceed to insert the sidecar container. We use a ConfigMap to store the sidecar container spec. The ConfigMap defines the container image, server port, etc. The handler should return a JSON patch to the Admission Controller. The Admission Webhook provides a helper function to create a patch from the original JSON and the modified JSON.

# Deployment

To deploy a Mutating Webhook:

1.  Install Cert Manager using Helm
2.  Setup a certificate for https calls; for development purposes, we will use a self-signed certificate. In the production environment, we have to use an actual certificate.
3.  We have to create an Object of kind MutatingWebhookConfiguration
4.  Create a service that listens on a port
5.  Create a Pod that runs the webhook application

To make it easy to install the Cert Manager and deploy our Mutating Webhook, I have created a Makefile that includes all the deployment targets. Hers is the Makefile.

  

    # Image URL to use all building/pushing image targets  
    IMG ?= sidecar-injector:latest  
      
    # Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)  
    ifeq (,$(shell go env GOBIN))  
    GOBIN=$(shell go env GOPATH)/bin  
    else  
    GOBIN=$(shell go env GOBIN)  
    endif  
      
    all: webhook  
      
    # Build manager binary  
    webhook:  
      go build -o bin/webhook main.go  
      
    # Run against the configured Kubernetes cluster in ~/.kube/config  
    run: webhook  
      go run ./main.go  
      
    uninstall:  
      kubectl delete -f deployments/  
      
    uninstall-cert: webhook  
      kubectl delete -f certs/  
      
    uninstall-sidecarconfig: webhook  
      kubectl delete -f config/  
      
    deploy-sidecarconfig: webhook  
      kubectl apply -f config/  
      
    deploy-cert: webhook  
      kubectl apply -f certs/  
      
    deploy: webhook  
      kubectl apply -f deployments/  
      
    # Build the docker image  
    docker-build: webhook  
      docker build . -t ${IMG}  
      
    # Push the docker image  
    docker-push:  
      docker push ${IMG}  
      
    install-cert-manager:  
      kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v1.0.2/cert-manager.yaml  
      
    deploy-sample:  
      kubectl apply -f sample/

To install the cert-manager, use the following command:

    make install-cert-manager

This command will install the cert-manager to your cluster. If the installation is successful, you can see the cert-manager running. The command `kubectl get all -n cert-manager` will list all the objects in the cert-manager namespace.

![Certificate Manager](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/certmanager.png?token=AA46XG5OOO7BGS7CTYXU2RK7R27KQ)

We should create a self-signed certificate for the webhook service since the Admission Controller will talk to the hook in a secure channel only. To create a self-signed certificate, use the following YAML definition.

    apiVersion: cert-manager.io/v1alpha2  
    kind: Issuer  
    metadata:  
      name: selfsigned-issuer  
      namespace: default  
    spec:  
      selfSigned: {}  
    ---  
    apiVersion: cert-manager.io/v1alpha2  
    kind: Certificate  
    metadata:  
      name: selfsigned-cert  
      namespace: default  
    spec:  
      secretName: sidecar-injector-certs  
      dnsNames:  
        - sidecar-injector-service.default.svc  
        - sidecar-injector-service.default.svc.cluster.local  
      issuerRef:  
        name: selfsigned-issuer

You can install the certificate using the following command:

    make deploy-cert

You can check the deployment using the command `kubectl get certificates`.

![Certificate](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/certificate.png?token=AA46XG2O4SW4A2CQOFFPRL27R27PW)

Once we install the cert-manager and self-signed certificate, we need to create a ConfigMap to store the sidecar container spec. Here is the YAML file definition.

    apiVersion: v1  
    kind: ConfigMap  
    metadata:  
      name: sidecar-injector-configmap  
      namespace: default  
    data:  
      sidecarconfig.yaml: |  
        containers:  
        - name: logger  
          image: localhost:5000/krvarma/logserver:latest  
          imagePullPolicy: IfNotPresent  
          env:  
            - name: LOGGER_PORT  
              value: "8082"

To deploy the ConfigMap, use the command:

    make deploy-sidecarconfig

Check the ConfigMap deployment using the command `kubectl get configmaps`

Before deploying the mutating webhook and pod, we need to build and push the webhook to the registry. The following command will create the docker image and push it to the registry. Note that I have a local registry running on the localhost; you have to replace the container registry URL according to your settings.

    IMG=localhost:5000/krvarma/sidecar-injector:latest make docker-build docker-push

Now we should create the MutatingWebhookConfiguration. The YAML looks like:

    apiVersion: v1  
    kind: Service  
    metadata:  
      name: sidecar-injector-service  
      labels:  
        app: sidecar-injector  
    spec:  
      ports:  
      - port: 8443  
        targetPort: 8443  
      selector:  
        app: sidecar-injector  
    ---  
    apiVersion: admissionregistration.k8s.io/v1beta1  
    kind: MutatingWebhookConfiguration  
    metadata:  
      creationTimestamp: null  
      name: sidecar-injector-configuration  
      annotations:  
        cert-manager.io/inject-ca-from: default/selfsigned-cert  
    webhooks:  
    - clientConfig:  
        caBundle: Cg==  
        service:  
          name: sidecar-injector-service    
          path: /mutate  
          port: 8443  
          namespace: "default"  
      sideEffects: None  
      admissionReviewVersions: ["v1beta1"]  
      failurePolicy: Fail  
      name: mpod.kb.io  
      rules:  
      - apiGroups:  
        - ""  
      apiVersions:  
        - v1  
        operations:  
        - CREATE  
        - UPDATE  
        resources:  
        - pods  
        scope: "Namespaced"

To install the Mutating Webhook, service and webhook deployment, use the following command:

    make deploy

This command will install the MutatingWebhookConfiguration and Service. To check the deployment, use the command `kubectl get MutatingWebhookConfigurations`  

![MutatingWebhookConfiguration](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/MutatingWebhookConfigurations.png?token=AA46XGYUKHWQRK3XQXSQKBS7R3AAG)

![Service](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/services.png?token=AA46XGY3TOFFGJY5NBD5G327R3ADS)

For Mutating Webhooks, the apiVersion should be either admissionregistration.k8s.io/v1beta1 or admissionregistration.k8s.io/v1. The metadata section defines the timestamp, name, annotations, etc. The annotation is crucial since we are using a self-signed certificate for HTTPS API. Next comes the webhooks section, which defines the webhook configuration, like caBundle, service name, service port, etc.

Now we have all the necessary deployment for the webhook; we need to deploy the log server.

For testing purposes, I have written a sample log server and client. I am using Golang to program the tool. Here is the source for the server and client. The server and client code are in the sclogger folder. Move to the sclogger folder and issue the following commands.

    package main
    
    import (
    	"encoding/json"
    	"fmt"
    	"io/ioutil"
    	"log"
    	"net/http"
    	"os"
    	"time"
    )
    
    type Log struct {
    	Tag     string `json:"tag"`
    	Message string `json:"message"`
    }
    
    // Get environment variable, if it is not found return default value
    func getEnv(key string, defvalue string) string {
    	value := os.Getenv(key)
    
    	if len(value) <= 0 {
    		value = defvalue
    	}
    
    	return value
    }
    
    func getAddr(port string) string {
    	return fmt.Sprintf(":%v", port)
    }
    
    func main() {
    	log.Print("Logger started")
    
    	http.HandleFunc("/info", LogHadler)
    	http.HandleFunc("/error", LogHadler)
    	http.HandleFunc("/warning", LogHadler)
    
    	addr := getAddr(getEnv("LOGGER_PORT", "8082"))
    
    	log.Printf("Log server listening on %v", addr)
    
    	http.ListenAndServe(addr, nil)
    }
    
    func LogHadler(w http.ResponseWriter, r *http.Request) {
    	var logLevel string
    
    	switch r.URL.Path {
    	case "/info":
    		logLevel = "INFO"
    	case "/error":
    		logLevel = "ERROR"
    	case "/warning":
    		logLevel = "WARNING"
    	default:
    		logLevel = "INFO"
    	}
    
    	switch r.Method {
    	case "POST":
    		reqBody, err := ioutil.ReadAll(r.Body)
    		if err != nil {
    			log.Fatal(err)
    		}
    
    		var log Log
    
    		json.Unmarshal(reqBody, &log)
    
    		fmt.Printf("%s %s %s:%s\n",
    			time.Now().Format("2006/01/02 15:04:05"),
    			logLevel,
    			log.Tag,
    			log.Message)
    
    		w.Write([]byte("Received Log request\n"))
    	default:
    		w.WriteHeader(http.StatusNotImplemented)
    		w.Write([]byte(http.StatusText(http.StatusNotImplemented)))
    	}
    }

Here is the client code.

    package main
    
    import (
    	"bytes"
    	"encoding/json"
    	"fmt"
    	"net/http"
    	"os"
    	"time"
    )
    
    // Get environment variable, if it is not found return default value
    func getEnv(key string, defvalue string) string {
    	value := os.Getenv(key)
    
    	if len(value) <= 0 {
    		value = defvalue
    	}
    
    	return value
    }
    
    func logMessage(path string, tag string, message string) {
    	body, err := json.Marshal(map[string]string{
    		"tag":     tag,
    		"message": message,
    	})
    
    	if err != nil {
    		fmt.Print(err, "\n")
    		return
    	}
    
    	serverUrl := getEnv("LOG_SERVER", "http://localhost")
    	serverPort := getEnv("LOG_PORT", "8082")
    	url := fmt.Sprintf("%s:%s/%s", serverUrl, serverPort, path)
    
    	resp, err := http.Post(
    		url,
    		"application/json",
    		bytes.NewBuffer(body))
    
    	if err != nil {
    		fmt.Print(err, "\n")
    		return
    	}
    
    	fmt.Print(resp.Status)
    }
    
    func logInfo(tag string, message string) {
    	logMessage("info", tag, message)
    }
    
    func logWarning(tag string, message string) {
    	logMessage("warning", tag, message)
    }
    
    func logError(tag string, message string) {
    	logMessage("error", tag, message)
    }
    
    func main() {
    	// logInfo("SCLOGGER", "Information message")
    	// logWarning("SCLOGGER", "Warning message")
    	// logError("SCLOGGER", "Error message")
    
    	done := make(chan bool)
    	go forever()
    	<-done // Block forever
    }
    
    func forever() {
    	for {
    		logInfo(
    			"SCLOGGER",
    			fmt.Sprintf("Time is %v", time.Now()))
    		time.Sleep(time.Second * 10)
    	}
    }


We need to build and push these tools to the container registry. For this purpose also, I have created a Makefile to make life easier.

    ENV IMG=localhost:5000/krvarma/logserver:latest docker-build docker-push

    ENV IMG=localhost:5000/krvarma/logclient:latest docker-build docker-push

These commands will build and push the log server and client to the container registry. Note that I have a local registry running on the localhost; you have to replace the container registry URL according to your settings.

Now we have server and client tools are in the container registry, we can deploy our sample to the cluster. To deploy the deployment with log client, issue the following command.

    make deploy-sample

This command will deploy our sample to the cluster. If everything goes well, we can see our sample and the sidecar.

![Sidecar](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/deployments%20running.png?token=AA46XG5DGYJO443Q5CUCIN27R3BE6)  

You can check the logs to see if the sidecar is working correctly or not. To check the logs, issue the following `kubectl` command:

    kubectl logs loggerclient-deployment-5f5fc8cf67-pm8t5 logger

Here is the screenshot of the logs.

![logs](https://raw.githubusercontent.com/krvarma/mutating-webhook/master/images/logs.png?token=AA46XG6FIQAADPDHMQOBPAK7R3BIA)  

Now you have a Mutating Webhook that automatically injects a sidecar to deployments. The example used here is a straightforward example that handles the logs; in real scenarios, the requirement will be much more complicated. I hope this example gives a headstart to write Mutating Webhooks. In the next part of the article, we will explore how to create a Validating Webhook. Till then, Happy Coding!
