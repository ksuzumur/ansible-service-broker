//
// Copyright (c) 2017 Red Hat, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Red Hat trademarks are not licensed under Apache License, Version 2.
// No permission is granted to use or replicate Red Hat trademarks that
// are incorporated in this software or its documentation.
//

package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	kapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeversiontypes "k8s.io/apimachinery/pkg/version"
	"k8s.io/kubernetes/pkg/apis/authentication/v1"
	authzv1 "k8s.io/kubernetes/pkg/apis/authorization/v1"

	logging "github.com/op/go-logging"
	"github.com/openshift/ansible-service-broker/pkg/apb"
	"github.com/openshift/ansible-service-broker/pkg/broker"
	"github.com/openshift/ansible-service-broker/pkg/clients"
	"github.com/openshift/ansible-service-broker/pkg/dao"
	"github.com/openshift/ansible-service-broker/pkg/handler"
	"github.com/openshift/ansible-service-broker/pkg/registries"
)

// MsgBufferSize - The buffer for the message channel.
const MsgBufferSize = 20

// App - All the application pieces that are installed.
type App struct {
	broker   *broker.AnsibleBroker
	args     Args
	config   Config
	dao      *dao.Dao
	log      *Log
	registry []registries.Registry
	engine   *broker.WorkEngine
}

// CreateApp - Creates the application
func CreateApp() App {
	var err error
	app := App{}

	// Writing directly to stderr because log has not been bootstrapped
	if app.args, err = CreateArgs(); err != nil {
		os.Exit(1)
	}

	if app.args.Version {
		fmt.Println(Version)
		os.Exit(0)
	}

	fmt.Println("============================================================")
	fmt.Println("==           Starting Ansible Service Broker...           ==")
	fmt.Println("============================================================")

	// TODO: Let's take all these validations and delegate them to the client
	// pkg.
	if app.config, err = CreateConfig(app.args.ConfigFile); err != nil {
		os.Stderr.WriteString("ERROR: Failed to read config file\n")
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}

	if app.log, err = NewLog(app.config.Log); err != nil {
		os.Stderr.WriteString("ERROR: Failed to initialize logger\n")
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}

	// Initializing clients as soon as we have deps ready.
	err = initClients(app.log.Logger, app.config.Dao.GetEtcdConfig())
	if err != nil {
		app.log.Error(err.Error())
		os.Exit(1)
	}

	app.log.Debug("Connecting Dao")
	app.dao, err = dao.NewDao(app.config.Dao, app.log.Logger)

	k8scli, err := clients.Kubernetes(app.log.Logger)
	if err != nil {
		app.log.Error(err.Error())
		os.Exit(1)
	}

	restcli := k8scli.CoreV1().RESTClient()
	body, err := restcli.Get().AbsPath("/version").Do().Raw()
	if err != nil {
		app.log.Error(err.Error())
		os.Exit(1)
	}
	switch {
	case err == nil:
		var kubeServerInfo kubeversiontypes.Info
		err = json.Unmarshal(body, &kubeServerInfo)
		if err != nil && len(body) > 0 {
			app.log.Error(err.Error())
			os.Exit(1)
		}
		app.log.Info("Kubernetes version: %v", kubeServerInfo)
	case kapierrors.IsNotFound(err) || kapierrors.IsUnauthorized(err) || kapierrors.IsForbidden(err):
	default:
		app.log.Error(err.Error())
		os.Exit(1)
	}

	/*
	   // TokenReview attempts to authenticate a token to a known user.
	   // Note: TokenReview requests may be cached by the webhook token authenticator
	   // plugin in the kube-apiserver.
	   type TokenReview struct {
		metav1.TypeMeta `json:",inline"`
		// +optional
		metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`

		// Spec holds information about the request being evaluated
		Spec TokenReviewSpec `json:"spec" protobuf:"bytes,2,opt,name=spec"`

		// Status is filled in by the server and indicates whether the request can be authenticated.
		// +optional
		Status TokenReviewStatus `json:"status,omitempty" protobuf:"bytes,3,opt,name=status"`
	   }

	   // TokenReviewSpec is a description of the token authentication request.
	   type TokenReviewSpec struct {
		// Token is the opaque bearer token.
		// +optional
		Token string `json:"token,omitempty" protobuf:"bytes,1,opt,name=token"`
	   }

	   // TokenReviewStatus is the result of the token authentication request.
	   type TokenReviewStatus struct {
		// Authenticated indicates that the token was associated with a known user.
		// +optional
		Authenticated bool `json:"authenticated,omitempty" protobuf:"varint,1,opt,name=authenticated"`
		// User is the UserInfo associated with the provided token.
		// +optional
		User UserInfo `json:"user,omitempty" protobuf:"bytes,2,opt,name=user"`
		// Error indicates that the token couldn't be checked
		// +optional
		Error string `json:"error,omitempty" protobuf:"bytes,3,opt,name=error"`
	   }
	*/
	app.log.Notice("================== BEGIN TOKEN ===============")

	app.log.Debug("Creating an auth client")
	authcli := k8scli.AuthenticationV1()
	app.log.Debug("calling token review")
	// so the nil needs to be a TokenReview struct. And the Spec needs to be the
	// Token.

	tr := &v1.TokenReview{
		ObjectMeta: metav1.ObjectMeta{
			Name: "asb-token-review",
		},
		Spec: v1.TokenReviewSpec{
			Token: "ZGVhZGJlZWY=", // deadbeef
		},
	}

	tokenreview, err := authcli.TokenReviews().Create(tr)
	// the tokenreview returned will have a  TokenReviewStatus which contains
	// the userinfo which we need.
	if err != nil {
		app.log.Errorf("Error calling token review. %#v", err)
		os.Exit(1)
	}

	if tokenreview.Status.Authenticated {
		app.log.Debug("We have an authenticated token")
		app.log.Debugf("userinfo: %v", tokenreview.Status.User)
	} else {
		app.log.Debug("We have an UNauthenticated token")
		app.log.Debugf("Error: %v", tokenreview.Status.Error)
	}
	app.log.Notice("================== END TOKEN ===============")

	app.log.Notice("================== BEGIN SAR ===============")
	app.log.Debug("Creating an authz client")
	authzcli := k8scli.AuthorizationV1()
	app.log.Debug("calling subject access review")

	/*
			type SubjectAccessReviewSpec struct {
		    // ResourceAuthorizationAttributes describes information for a resource access request
		    // +optional
		    ResourceAttributes *ResourceAttributes `json:"resourceAttributes,omitempty" protobuf:"bytes,1,opt,name=resourceAttributes"`
		    // NonResourceAttributes describes information for a non-resource access request
		    // +optional
		    NonResourceAttributes *NonResourceAttributes `json:"nonResourceAttributes,omitempty" protobuf:"bytes,2,opt,name=nonResourceAttributes"`

		    // User is the user you're testing for.
		    // If you specify "User" but not "Groups", then is it interpreted as "What if User were not a member of any groups
		    // +optional
		    User string `json:"user,omitempty" protobuf:"bytes,3,opt,name=user"`
		    // Groups is the groups you're testing for.
		    // +optional
		    Groups []string `json:"groups,omitempty" protobuf:"bytes,4,rep,name=groups"`
		    // Extra corresponds to the user.Info.GetExtra() method from the authenticator.  Since that is input to the authorizer
		    // it needs a reflection here.
		    // +optional
		    Extra map[string]ExtraValue `json:"extra,omitempty" protobuf:"bytes,5,rep,name=extra"`
		    // UID information about the requesting user.
		    // +optional
		    UID string `json:"uid,omitempty" protobuf:"bytes,6,opt,name=uid"`
		}
	*/
	sar := &authzv1.SubjectAccessReview{
		ObjectMeta: metav1.ObjectMeta{
			Name: "asb-sar-review",
		},
		Spec: authzv1.SubjectAccessReviewSpec{}, // need to fill this out
	}
	dasar, sarerr := authzcli.SubjectAccessReviews().Create(sar)
	if sarerr != nil {
		app.log.Errorf("Error calling subject access review. %#v", sarerr)
		os.Exit(1)
	}

	if dasar.Status.Allowed {
		app.log.Debug("We have access")
	} else {
		app.log.Debug("We DO NOT have access")
		app.log.Debugf("Reason: %v, Error: %v", dasar.Status.Reason, dasar.Status.EvaluationError)
	}
	app.log.Notice("================== END SAR ===============")

	app.log.Debug("Connecting Registry")
	for _, r := range app.config.Registry {
		reg, err := registries.NewRegistry(r, app.log.Logger)
		if err != nil {
			app.log.Errorf(
				"Failed to initialize %v Registry err - %v \n", r.Name, err)
			os.Exit(1)
		}
		app.registry = append(app.registry, reg)
	}

	app.log.Debug("Initializing WorkEngine")
	app.engine = broker.NewWorkEngine(MsgBufferSize)
	err = app.engine.AttachSubscriber(
		broker.NewProvisionWorkSubscriber(app.dao, app.log.Logger),
		broker.ProvisionTopic)
	if err != nil {
		app.log.Errorf("Failed to attach subscriber to WorkEngine: %s", err.Error())
		os.Exit(1)
	}
	err = app.engine.AttachSubscriber(
		broker.NewDeprovisionWorkSubscriber(app.dao, app.log.Logger),
		broker.DeprovisionTopic)
	if err != nil {
		app.log.Errorf("Failed to attach subscriber to WorkEngine: %s", err.Error())
		os.Exit(1)
	}
	app.log.Debugf("Active work engine topics: %+v", app.engine.GetActiveTopics())

	apb.InitializeSecretsCache(app.config.Secrets, app.log.Logger)
	app.log.Debug("Creating AnsibleBroker")
	if app.broker, err = broker.NewAnsibleBroker(
		app.dao, app.log.Logger, app.config.Openshift, app.registry, *app.engine, app.config.Broker,
	); err != nil {
		app.log.Error("Failed to create AnsibleBroker\n")
		app.log.Error(err.Error())
		os.Exit(1)
	}

	return app
}

// Recover - Recover the application
// TODO: Make this a go routine once we have a strong and well tested
// recovery sequence.
func (a *App) Recover() {
	msg, err := a.broker.Recover()

	if err != nil {
		a.log.Error(err.Error())
	}

	a.log.Notice(msg)
}

// Start - Will start the application to listen on the specified port.
func (a *App) Start() {
	// TODO: probably return an error or some sort of message such that we can
	// see if we need to go any further.

	if a.config.Broker.Recovery {
		a.log.Info("Initiating Recovery Process")
		a.Recover()
	}

	if a.config.Broker.BootstrapOnStartup {
		a.log.Info("Broker configured to bootstrap on startup")
		a.log.Info("Attempting bootstrap...")
		if _, err := a.broker.Bootstrap(); err != nil {
			a.log.Error("Failed to bootstrap on startup!")
			a.log.Error(err.Error())
			os.Exit(1)
		}
		a.log.Notice("Broker successfully bootstrapped on startup")
	}

	interval, err := time.ParseDuration(a.config.Broker.RefreshInterval)
	a.log.Debug("RefreshInterval: %v", interval.String())
	if err != nil {
		a.log.Error(err.Error())
		a.log.Error("Not using a refresh interval")
	} else {
		ticker := time.NewTicker(interval)
		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()
		go func() {
			for {
				select {
				case v := <-ticker.C:
					a.log.Info("Broker configured to refresh specs every %v seconds", interval)
					a.log.Info("Attempting bootstrap at %v", v.UTC())
					if _, err := a.broker.Bootstrap(); err != nil {
						a.log.Error("Failed to bootstrap")
						a.log.Error(err.Error())
					}
					a.log.Notice("Broker successfully bootstrapped")
				case <-ctx.Done():
					ticker.Stop()
					return
				}
			}
		}()
	}

	a.log.Notice("Ansible Service Broker Started")
	listeningAddress := "0.0.0.0:1338"
	if a.args.Insecure {
		a.log.Notice("Listening on http://%s", listeningAddress)
		err = http.ListenAndServe(":1338",
			handler.NewHandler(a.broker, a.log.Logger, a.config.Broker))
	} else {
		a.log.Notice("Listening on https://%s", listeningAddress)
		err = http.ListenAndServeTLS(":1338",
			a.config.Broker.SSLCert,
			a.config.Broker.SSLCertKey,
			handler.NewHandler(a.broker, a.log.Logger, a.config.Broker))
	}
	if err != nil {
		a.log.Error("Failed to start HTTP server")
		a.log.Error(err.Error())
		os.Exit(1)
	}
}

func initClients(log *logging.Logger, ec clients.EtcdConfig) error {
	// Designed to panic early if we cannot construct required clients.
	// this likely means we're in an unrecoverable configuration or environment.
	// Best we can do is alert the operator as early as possible.
	//
	// Deliberately forcing the injection of deps here instead of running as a
	// method on the app. Forces developers at authorship time to think about
	// dependencies / make sure things are ready.
	log.Notice("Initializing clients...")
	log.Debug("Trying to connect to etcd")

	etcdClient, err := clients.Etcd(ec, log)
	if err != nil {
		return err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	version, err := etcdClient.GetVersion(ctx)
	if err != nil {
		return err
	}

	log.Info("Etcd Version [Server: %s, Cluster: %s]", version.Server, version.Cluster)

	log.Debug("Connecting to Cluster")
	_, err = clients.Kubernetes(log)
	if err != nil {
		return err
	}

	return nil
}
