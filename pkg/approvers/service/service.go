package service

import (
	"flag"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/kapprover/pkg/approvers"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
)

const (
	kubeletServiceAccountGroup = "system:serviceaccount"
)

var serviceAccountName = flag.String("service-account", "", "Service account to approve CSRs for")
var namespace = flag.String("service-account-namespace", "default", "Namespace of service account")

func init() {
	approvers.Register("service", &Service{})
}

// Always is an Approver that automatically approves any pending CSR submitted
// by kubelets during their TLS bootstrapping process, without making any kind
// of validation besides checking that the requester's user/group are
// respectively kubeletBootstrapUsername / kubeletBootstrapGroup.
type Service struct{}

// Approve approves CSRs in a loop.
func (*Service) Approve(client v1beta1.CertificateSigningRequestInterface, request *certificates.CertificateSigningRequest) error {
	condition := certificates.CertificateSigningRequestCondition{
		Type:    certificates.CertificateApproved,
		Reason:  "AutoApproved",
		Message: "Auto approving of all CSRs from service account: " + *serviceAccountName,
	}

	for {
		// Verify that the CSR hasn't been approved or denied already.
		//
		// There are only two possible conditions (CertificateApproved and
		// CertificateDenied). Therefore if the CSR already has a condition,
		// it means that the request has already been approved or denied, and that
		// we should ignore the request.
		if len(request.Status.Conditions) > 0 {
			log.Infof("Ignoring already approved/denied CSR")
			return nil
		}

		fullUsername := strings.Join([]string{kubeletServiceAccountGroup, *namespace, *serviceAccountName}, ":")

		// Ensure the CSR has been submitted by a kubelet performing its TLS
		// bootstrapping by checking the username and the group.
		if request.Spec.Username != fullUsername {
			log.Infof("Denying CSR due to username not matching service account: %s != %s", request.Spec.Username, fullUsername)
			return nil
		}

		// Approve the CSR.
		request.Status.Conditions = append(request.Status.Conditions, condition)
		log.Info("Approving CSR!")

		// Submit the updated CSR.
		if _, err := client.UpdateApproval(request); err != nil {
			if strings.Contains(err.Error(), "the object has been modified") {
				// The CSR might have been updated by a third-party, retry until we
				// succeed.
				request, err = client.Get(request.ObjectMeta.Name, meta.GetOptions{})
				if err != nil {
					return err
				}
				continue
			}

			return err
		}

		log.Infof("Successfully approved %q", request.ObjectMeta.Name)

		return nil
	}
}
