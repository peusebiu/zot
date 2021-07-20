module github.com/anuvu/zot

go 1.14

require (
	github.com/99designs/gqlgen v0.12.2
	github.com/Masterminds/semver v1.5.0
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751
	github.com/apex/log v1.4.0
	github.com/aquasecurity/trivy v0.0.0-00010101000000-000000000000
	github.com/briandowns/spinner v1.11.1
	github.com/chartmuseum/auth v0.4.0
	github.com/containers/common v0.26.0
	github.com/containers/image/v5 v5.13.2
	github.com/docker/docker v20.10.7+incompatible // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/getlantern/deepcopy v0.0.0-20160317154340-7f45deb8130a
	github.com/go-chi/chi v4.0.2+incompatible // indirect
	github.com/go-ldap/ldap/v3 v3.1.3
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/google/go-containerregistry v0.0.0-20200331213917-3d03ed9b1ca2
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.8.0
	github.com/json-iterator/go v1.1.11
	github.com/mitchellh/mapstructure v1.1.2
	github.com/moby/sys/mount v0.2.0 // indirect
	github.com/moby/term v0.0.0-20201216013528-df9cb8a40635 // indirect
	github.com/nmcclain/asn1-ber v0.0.0-20170104154839-2661553a0484 // indirect
	github.com/nmcclain/ldap v0.0.0-20191021200707-3b3b69a7e9e3
	github.com/olekukonko/tablewriter v0.0.4
	github.com/onsi/ginkgo v1.16.4 // indirect
	github.com/onsi/gomega v1.13.0 // indirect
	github.com/opencontainers/distribution-spec v1.0.0-rc0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.2-0.20190823105129-775207bd45b6
	github.com/opencontainers/umoci v0.4.7-0.20200704224433-977db481b72c
	github.com/phayes/freeport v0.0.0-20180830031419-95f893ade6f2
	github.com/rs/zerolog v1.17.2
	github.com/smartystreets/goconvey v1.6.4
	github.com/spf13/cobra v1.0.0
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.7.0
	github.com/swaggo/http-swagger v0.0.0-20190614090009-c2865af9083e
	github.com/swaggo/swag v1.6.3
	github.com/vektah/gqlparser/v2 v2.0.1
	go.etcd.io/bbolt v1.3.6
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	gopkg.in/resty.v1 v1.12.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/aquasecurity/trivy => github.com/anuvu/trivy v0.9.2-0.20200731014147-c5f97b59c172

replace github.com/aquasecurity/fanal => github.com/anuvu/fanal v0.0.0-20200731014233-a1725a9d379f

replace github.com/aquasecurity/trivy-db => github.com/anuvu/trivy-db v0.0.0-20200623200932-d185809a68f7
