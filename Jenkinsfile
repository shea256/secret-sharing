pipeline {
  agent {
    label "jenkins-python36"
  }

  /*
     The environment directive specifies a sequence of key-value pairs which
     will be defined as environment variables for the all steps, or
     stage-specific steps, depending on where the environment directive is
     located within the Pipeline.

     This directive supports a special helper method credentials() which can be
     used to access pre-defined Credentials by their identifier in the Jenkins
     environment. For Credentials which are of type "Secret Text",
     the credentials() method will ensure that the environment variable
     specified contains the Secret Text contents. For Credentials which are of
     type "Standard username and password", the environment variable specified
     will be set to username:password and two additional environment variables
     will be automatically be defined:
     MYVARNAME_USR and MYVARNAME_PSW respectively.

    These variables will be passed to the docker build container via the ENV
    directive. So please be careful with passing in credentials.
    To ensure creads are kept from showing up in logs and echo'd out to a job
    Leaverage the Jenkins credential store.
    https://jenkins.io/doc/book/using/using-credentials/#types-of-credentials
  */
  environment {
    NEXUS = credentials('jx-nexus-pypi')
    TWINE_REPOSITORY_URL = 'http://nexus/repository/sl-pypi-internal/'
  }

  /*
     STAGES
     Containing a sequence of one or more stage directives,
     the stages section is where the bulk of the "work" described by a
     Pipeline will be located. At a minimum it is recommended that stages
     contain at least one stage directive for each discrete part of the
     continuous delivery process, such as Build, Test, and Deploy.
  */

  stages {
    stage('Security Checks') {
      when {
        branch 'PR-*'
      }
      steps {
        container('python') {
          sh "pip3 install safety"
          sh "safety check -r requirements.txt"
        }
      }
    }
    stage('Run Tests') {
      when {
        branch 'PR-*'
      }
      steps {
        container('python') {
          sh "pip3 install setuptools==40.2.0 safety"
          sh "pip3 install -r requirements.txt"
					sh "python3 unit_tests.py"
        }
      }
    }

    stage('Build') {
      when {
        branch 'PR-*'
      }

      /*
         The steps section defines a series of one or more steps to be executed
         in a given stage directive.
      */
      steps {
        container('python') {
          sh "pip3 install wheel"
          sh "python3 setup.py sdist bdist_wheel"
        }
      }

      /*
         The post section defines one or more additional steps that are run
         upon the completion of a Pipeline’s or stage’s run (depending on the
         location of the post section within the Pipeline). post can support
         any of of the following post-condition blocks: always, changed, fixed,
         regression, aborted, failure, success, unstable, unsuccessful,
         and cleanup. These condition blocks allow the execution of steps
         inside each condition depending on the completion status of the
         Pipeline or stage. The condition blocks are executed in the order
         shown
      */
      post {
        always {
            // archiveArtifacts will give you a link in the Jenkins iterface
            // Where you can download the built artifact.
            archiveArtifacts (
              allowEmptyArchive: true,
              artifacts: 'dist/*',
              fingerprint: true
            )
        }
      }
    }

    stage('upload to pypi') {
      when {
        branch 'PR-*'
      }
      steps {
        container('python') {
          sh "pip install twine"
          sh "twine upload -u $NEXUS_USR -p $NEXUS_PSW dist/*"
        }
      }
    }
  }

  post {
    always {
      cleanWs()
    }
  }
}


