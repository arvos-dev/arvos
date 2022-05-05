from xml.etree import ElementTree

def parse_xml(filename):

    dep_list = []


    POM_FILE= filename
        
    namespaces = {'xmlns' : 'http://maven.apache.org/POM/4.0.0'}

    tree = ElementTree.parse(POM_FILE)
    root = tree.getroot()

    deps = root.findall(".//xmlns:dependency", namespaces=namespaces)
    for d in deps:
        groupId = d.find("xmlns:groupId", namespaces=namespaces)
        if groupId is None:
            groupId_text = ""
        else:
            groupId_text = groupId.text


        artifactId = d.find("xmlns:artifactId", namespaces=namespaces)
        if artifactId is None:
            artifactId_text = ""
        else:
            artifactId_text = artifactId.text

                
        version    = d.find("xmlns:version", namespaces=namespaces)
        
        if version is None:
            version_text = ""
        else:
            version_text = version.text
        
        dep_list.append({"groupId": groupId_text,"artifactId": artifactId_text, "version": version_text})

    return dep_list

def getGroupId(filename):
    namespaces = {'xmlns' : 'http://maven.apache.org/POM/4.0.0'}

    tree = ElementTree.parse(filename)
    root = tree.getroot()    

    return root.find("xmlns:groupId", namespaces=namespaces).text

def getArtifactId(filename):
    namespaces = {'xmlns' : 'http://maven.apache.org/POM/4.0.0'}

    tree = ElementTree.parse(filename)
    root = tree.getroot()

    return root.find("xmlns:artifactId", namespaces=namespaces).text