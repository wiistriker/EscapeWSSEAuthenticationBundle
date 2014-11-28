def project_owner = "escapestudios"
def project_name = "EscapeWSSEAuthenticationBundle"
def project = project_owner + "/" + project_name
def branches = [ "master" ] as String[]

branches.each {
    def branch = it

    job {
      name "${project}_${branch}".replaceAll("/","-")
      scm {
        git("git://github.com/${project}.git", branch)
      }
      triggers {
        githubPush()
      }
      steps {
        ant("build")
      }
      publishers {
        checkstyle("build/logs/checkstyle.xml")
        pmd("build/logs/pmd.xml")
        dry("build/logs/pmd-cpd.xml")
        //PlotPublisher (see below)
        //CloverPublisher (see below)
        publishHtml {
          report("build/code-browser", "Code Browser", "index.html", true)
        }
        archiveJavadoc {
          javadocDir "build/docs"
          keepAll false
        }
        archiveXUnit {
          phpUnit {
            pattern("build/logs/junit.xml")
            skipNoTestFiles(false)
            failIfNotNew(true)
            deleteOutputFiles(true)
            stopProcessingIfError(true)
          }
          thresholdMode ThresholdMode.PERCENT
        }
        //JDependRecorder (see below)
        violations(100) {
          checkstyle(10, 999, 999, "build/logs/checkstyle.xml")
          codenarc(10, 999, 999)
          cpd(10, 999, 999, "build/logs/pmd-cpd.xml")
          cpplint(10, 999, 999)
          csslint(10, 999, 999)
          findbugs(10, 999, 999)
          fxcop(10, 999, 999)
          gendarme(10, 999, 999)
          jcreport(10, 999, 999)
          jslint(10, 999, 999)
          pep8(10, 999, 999)
          pmd(10, 999, 999, "build/logs/pmd.xml")
          pylint(10, 999, 999)
          simian(10, 999, 999)
          stylecop(10, 999, 999)
        }
        mailer("dev+EscapeWSSEAuthenticationBundle@escapestudios.com")
      }
      configure {
        it / "publishers" / "hudson.plugins.plot.PlotPublisher" {
          plots {
            "hudson.plugins.plot.Plot" {
              title "A - Lines of code"
              yaxis "Lines of Code"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Lines of Code (LOC)"
                    string "Comment Lines of Code (CLOC)"
                    string "Non-Comment Lines of Code (NCLOC)"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Lines of Code (LOC),Comment Lines of Code (CLOC),Non-Comment Lines of Code (NCLOC)"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "123.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "B - Structures"
              yaxis "Count"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Functions"
                    string "Classes"
                    string "Namespaces"
                    string "Files"
                    string "Directories"
                    string "Methods"
                    string "Interfaces"
                    string "Constants"
                    string "Anonymous Functions"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Directories,Files,Namespaces,Interfaces,Classes,Methods,Functions,Anonymous Functions,Constants"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "1107599928.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "G - Average Length"
              yaxis "Average Non-Comment Lines of Code"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Average Method Length (NCLOC)"
                    string "Average Class Length (NCLOC)"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Average Class Length (NCLOC),Average Method Length (NCLOC)"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "523405415.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "H - Relative Cyclomatic Complexity"
              yaxis "Cyclomatic Complexity by Structure"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Cyclomatic Complexity / Lines of Code"
                    string "Cyclomatic Complexity / Number of Methods"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Cyclomatic Complexity / Lines of Code,Cyclomatic Complexity / Number of Methods"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "186376189.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "D - Types of Classes"
              yaxis "Count"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Abstract Classes"
                    string "Classes"
                    string "Concrete Classes"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Classes,Abstract Classes,Concrete Classes"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "594356163.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "E - Types of Methods"
              yaxis "Count"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Methods"
                    string "Static Methods"
                    string "Non-Static Methods"
                    string "Public Methods"
                    string "Non-Public Methods"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Methods,Non-Static Methods,Static Methods,Public Methods,Non-Public Methods"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "1019987862.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "F - Types of Constants"
              yaxis "Count"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Class Constants"
                    string "Global Constants"
                    string "Constants"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Constants,Global Constants,Class Constants"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "217648577.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
            "hudson.plugins.plot.Plot" {
              title "C - Testing"
              yaxis "Count"
              series {
                "hudson.plugins.plot.CSVSeries" {
                  file "build/logs/phploc.csv"
                  fileType "csv"
                  strExclusionSet {
                    string "Functions"
                    string "Classes"
                    string "Methods"
                    string "Test Classes"
                    string "Test Methods"
                  }
                  inclusionFlag "INCLUDE_BY_STRING"
                  exclusionValues "Classes,Methods,Functions,Test Classes,Test Methods"
                  displayTableFlag "false"
                }
              }
              group "phploc"
              numBuilds "100"
              csvFileName "174807245.csv"
              csvLastModification "0"
              style "line"
              useDescr "false"
            }
          }
        }

        it / "publishers" / "org.jenkinsci.plugins.cloverphp.CloverPublisher" {
          publishHtmlReport "true"
          reportDir "build/coverage"
          xmlLocation "build/logs/clover.xml"
          disableArchiving "false"
          healthyTarget {
            methodCoverage "70"
            conditionalCoverage "80"
            statementCoverage "80"
          }
          unhealthyTarget()
          failingTarget()
        }

        it / "publishers" / "hudson.plugins.jdepend.JDependRecorder" {
          configuredJDependFile "build/logs/jdepend.xml"
        }
      }
    }
}