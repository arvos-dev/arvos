from xml.etree import ElementTree

def parse_xml(filename):

    dep_list = []


    POM_FILE= filename
        
    namespaces = {'xmlns' : 'http://maven.apache.org/POM/4.0.0'}

    tree = ElementTree.parse(POM_FILE)
    root = tree.getroot()

    deps = root.findall(".//xmlns:dependency", namespaces=namespaces)
    for d in deps:
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
        
        dep_list.append({"artifactId": artifactId_text, "version": version_text})

    return dep_list