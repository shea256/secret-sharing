pipeline {
  agent {
    label "spring-builder"
  }


  environment {
    NEXUS = credentials('jx-nexus-pypi')
  }

  stages {
    stage('Security Checks') {
      when {
        branch 'PR-*'
      }
      steps {
        container('python') {
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
        branch 'master'
      }

      steps {
        container('python') {
          sh "python3 setup.py sdist bdist_wheel"
        }
      }

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
        branch 'master'
      }
      steps {
        container('python') {
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


