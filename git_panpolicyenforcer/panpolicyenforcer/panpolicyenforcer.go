// Copyright 2018 Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// nolint:lll
// Generates the mygrpcadapter adapter's resource yaml. It contains the adapter's configuration, name, supported template
// names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/panpolicyenforcer/config/config.proto -x "-s=false -n panpolicyenforcer -t authorization"

package panpolicyenforcer

import (
    "context"
    "fmt"
    "net"
    "net/http"
    "reflect"
    "google.golang.org/grpc"
    "bytes"
	rpc "github.com/gogo/googleapis/google/rpc"
    "istio.io/api/mixer/adapter/model/v1beta1"
    policy "istio.io/api/policy/v1beta1"
    "istio.io/istio/mixer/adapter/panpolicyenforcer/config"
    "istio.io/istio/mixer/template/authorization"
    "istio.io/istio/pkg/log"
    "istio.io/istio/mixer/pkg/status"
    "os"
	"io/ioutil"
	"encoding/json"
	"time"
)

type (
    // Server is basic server interface
    Server interface {
        Addr() string
        Close() error
        Run(shutdown chan error)
    }

    // MyGrpcAdapter supports metric template.
    MyGrpcAdapter struct {
        listener net.Listener
        server   *grpc.Server
    }

	// Security Policy definition
	SecurityPolicy struct {
        SourceService string `json:"source_service"`
        DestinationService string `json:"destination_service"`
        SourceNamespace string `json:"source_namespace"`
        DestinationNamespace string `json:"destination_namespace"`
        Protocol string `json:protocol`
	}
)

var _ authorization.HandleAuthorizationServiceServer = &MyGrpcAdapter{}
//var confSecPolicy2 = SecurityPolicy{}
var confSecPolicy2 []SecurityPolicy

// HandleLogEntry records log entries
func (s *MyGrpcAdapter) HandleAuthorization(ctx context.Context, in *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {

	var b bytes.Buffer
	log.Infof("New Mixer CHECK REQUEST. HandleAuthorization invoked")
    cfg := &config.Params{}

    if in.AdapterConfig != nil {
        if err := cfg.Unmarshal(in.AdapterConfig.Value); err != nil {
            log.Errorf("error unmarshalling adapter config: %v", err)
            return nil, err
        }
    }

	b.WriteString(fmt.Sprintf("HandleAuthorization invoked with:\n  Adapter config: %s\n  Instances: %s\n",
        cfg.String(), in.Instance))
    log.Infof("Instance value: %v", in.Instance.Name)

	if in.Instance.Action.Properties != nil {
        for key, val := range in.Instance.Action.Properties {
            log.Infof("Property key %s : Value : %s : %s", key, val.Value, decodeValue(val.Value))
        }
    }

	sp :=populateSecurityPolicyParams(in)

	if cfg.FilePath == "" {
        fmt.Println(b.String())
    } else {
			var ret int
			if _, err := os.Stat(cfg.FilePath); os.IsNotExist(err) {
				fmt.Println("File does not exist. Create it...")
				ret = 1
			}

			if ret == 1 {
				_, err := os.OpenFile(cfg.FilePath, os.O_RDONLY|os.O_CREATE, 0666)
				if err != nil {
					log.Errorf("error creating file: %v", err)
				}

			}

			f, err:= os.OpenFile(cfg.FilePath, os.O_APPEND|os.O_WRONLY, 0666)
			if err != nil {
				log.Errorf("error opening file for append: %v", err)
				return nil, err
			}
		defer f.Close()

        log.Infof("writing instances to file %s", f.Name())
        if _, err = f.Write(b.Bytes()); err != nil {
            log.Errorf("error writing to file: %v", err)
        }
	}

    var found bool
	found,_ = checkAuthorization(confSecPolicy2, sp)

	cr := v1beta1.CheckResult{}
	if found {
			log.Infof("RESULT: ACCESS ALLOWED. Request parameters match configured security policies.")
		    cr.Status =	status.WithMessage(rpc.OK, "Match found")
		    cr.ValidDuration = 100
		    cr.ValidUseCount = 500
	} else {
			log.Infof("RESULT: ACCESS DENIED. Request parameters do not match configured security policies.")
		    cr.Status =	status.WithMessage(rpc.PERMISSION_DENIED, "Match not found")
		    cr.ValidDuration = 500
		    cr.ValidUseCount = 600
	}

    return &cr, nil
}

func checkAuthorization(confSecPolicy []SecurityPolicy, runtimeSecPolicy SecurityPolicy) (retValue bool, e error) {

	for idx, item := range confSecPolicy {
        log.Infof("Comparing configured security policy %d", idx)
		log.Infof("Configured security policy: %s", item)
		log.Infof("Runtime security policy: %s", runtimeSecPolicy)
		if item.SourceService == runtimeSecPolicy.SourceService &&
			item.SourceNamespace == runtimeSecPolicy.SourceNamespace &&
			item.DestinationNamespace == runtimeSecPolicy.DestinationNamespace &&
			item.DestinationService == runtimeSecPolicy.DestinationService &&
			item.Protocol == runtimeSecPolicy.Protocol {
			return true, nil
		}
	}
	log.Info("No security policy match found. Returning denied.")
	return false,nil
}

func decodeDimensions(in map[string]*policy.Value) map[string]interface{} {
    out := make(map[string]interface{}, len(in))
    for k, v := range in {
        out[k] = decodeValue(v.GetValue())
    }
    return out
}


func populateSecurityPolicyParams(in *authorization.HandleAuthorizationRequest) (sp SecurityPolicy){

	sec_policy := SecurityPolicy{}

    log.Infof("Subject -> User: %s", in.Instance.Subject.User)
	log.Infof("Subject -> Group: %s", in.Instance.Subject.Groups)


	for key, val := range in.Instance.Subject.Properties {
		if key == "source_namespace" {
			log.Infof("Source namespace: %s", decodeValue(val.Value))
			sec_policy.SourceNamespace = decodeValue(val.Value).(string)
		} else if key == "source_service" {
			log.Infof("Source service: %s", decodeValue(val.Value))
			sec_policy.SourceService = decodeValue(val.Value).(string)
		}
	}
	for key, val := range in.Instance.Action.Properties {
		if key == "protocol" {
			log.Infof("Action -> Properties -> protocol: %s", decodeValue(val.Value))
			sec_policy.Protocol = decodeValue(val.Value).(string)
		}
	}
    log.Infof("Action -> Namespace: %s", in.Instance.Action.Namespace)
	log.Infof("Action -> Service: %s", in.Instance.Action.Service)
	sec_policy.DestinationNamespace = in.Instance.Action.Namespace
	sec_policy.DestinationService = in.Instance.Action.Service
	return sec_policy
}


func decodeValue(in interface{}) interface{} {
    switch t := in.(type) {
    case *policy.Value_StringValue:
        return t.StringValue
    case *policy.Value_Int64Value:
        return t.Int64Value
    case *policy.Value_DoubleValue:
        return t.DoubleValue
    case *policy.Value_IpAddressValue:
        ipV := t.IpAddressValue.Value
        ipAddress := net.IP(ipV)
        str := ipAddress.String()
        return str
    case *policy.Value_DurationValue:
        return t.DurationValue.Value.String()
    default:
        return fmt.Sprintf("%v", in)
    }
}

func retry(attempts int, sleep time.Duration, fn func() error) error {
    if err := fn(); err != nil {
        if s, ok := err.(stop); ok {
            // Return the original error for later checking
            return s.error
        }

        if attempts--; attempts > 0 {
            time.Sleep(sleep * time.Second)
            return retry(attempts, 2*sleep, fn)
        }
        return err
    }
    return nil
}

type stop struct {
    error
}

// Retrieve security policies from Policy Server
func remoteFetchSecurityPolicy() error {
	// the idea is to retrieve 
	// the endpoint for the Policy server 
	// from environment variables 

	// Retrieve the API server URL from the 
	// the environment variable SECURITY_POLICY_API_ENDPOINT

	security_policy_endpoint := os.Getenv("SECURITY_POLICY_API_ENDPOINT")
	if security_policy_endpoint == "" {
		log.Fatal("Unable to retrieve the security policy endpoint. Please check configuration")
	}

	// TODO: need to build a retry mechanism.
	// Its quite possible that the policy server
	// might not be ready when we attempt to connect. 

	// TODO: might also need to build some sort of authentication 
   //        mechanism.
	req, err := http.NewRequest("GET", security_policy_endpoint, nil)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Infof("Error occurred while trying to retrieve security policies from remote endpoint")
		return err
	}
	body, err:= ioutil.ReadAll(resp.Body)
	log.Infof("Response from the Security Policy API Server: %s", string(body))
	resp.Body.Close()
	_ = json.Unmarshal(body, &confSecPolicy2)
	log.Infof("Unmarshaled data information: %s %s", confSecPolicy2, reflect.TypeOf(confSecPolicy2))
	return nil
}


// Addr returns the listening address of the server
func (s *MyGrpcAdapter) Addr() string {
    return s.listener.Addr().String()
}

// Run starts the server run
func (s *MyGrpcAdapter) Run(shutdown chan error) {
    shutdown <- s.server.Serve(s.listener)
}

// Close gracefully shuts down the server; used for testing
func (s *MyGrpcAdapter) Close() error {
    if s.server != nil {
        s.server.GracefulStop()
    }

    if s.listener != nil {
        _ = s.listener.Close()
    }

    return nil
}

// NewMyGrpcAdapter creates a new IBP adapter that listens at provided port.
func NewMyGrpcAdapter(addr string) (Server, error) {
    if addr == "" {
        addr = "0"
    }
    listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
    if err != nil {
        return nil, fmt.Errorf("unable to listen on socket: %v", err)
    }
    s := &MyGrpcAdapter{
        listener: listener,
    }
    fmt.Printf("listening on \"%v\"\n", s.Addr())
    s.server = grpc.NewServer()
    authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
	retry(20, 5, remoteFetchSecurityPolicy)
    return s, nil
}
