// Shared library configuration
def sharedLibJenkinsName = "atom-shared-library" // The "shared library" name in Jenkins configuration
def sharedLibBranch = "master" // The branch of the "shared library" to be used

// Load the shared library packages
def pipelinesLib = library("$sharedLibJenkinsName@$sharedLibBranch").atom.pipelines

// Instantiate the pipeline
pipeline = pipelinesLib.K8sPipeline.new(this)
pipeline.checkoutDir = 'zot'
pipeline.disableEmailsOnStart = true
pipeline.disableEmailsOnSuccess = true
pipeline.disablePrCommentOnSuccess = true
pipeline.customPodYaml = '''
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
    - name: jnlp
      image: aci-docker-reg.cisco.com/devops/jnlp-slave:alpine
      volumeMounts:
        - mountPath: /home/jenkins
          name: workspace-volume-m
      args:
        - -disableHttpsCertValidation
        - $(JENKINS_SECRET)
        - $(JENKINS_NAME)
    - name: build
      image: aci-docker-reg.cisco.com/devops/ci:1.0.0-beta1
      tty: true
      securityContext:
        runAsUser: 0
        privileged: true
        resources:
          requests:
            cpu: 0.02
          limits:
            cpu: 32
      volumeMounts:
        - mountPath: /home/jenkins
          name: workspace-volume-m
      command:
        - /sbin/dumb-init
      args:
        - /bin/sleep
        - infinity
  nodeSelector:
    project: case-jenkins
  volumes:
    - name: workspace-volume-m
      emptyDir: {}
'''

pipeline.executeWithClosure() {
    container('build') {
        withEnv(['HTTP_PROXY=http://proxy.esl.cisco.com:8080','HTTPS_PROXY=http://proxy.esl.cisco.com:8080']) {
            pipeline.executeMakeTarget("all")
        }
    }
}
