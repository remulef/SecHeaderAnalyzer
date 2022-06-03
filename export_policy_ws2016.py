import xml.etree.ElementTree as ET
import re
import os
import csv
import collections
import datetime
now = datetime.datetime.now()
now = now.strftime("%Y%m%d%H%M%S")

def unique(list1):
    unique_list = []
    for x in list1:
        if x not in unique_list:
            unique_list.append(x)
    return unique_list


def unique_list_dic(list1):
    unique_list = []
    final= []
    for x in list1:
        if x['Reference_CIS']+x['title'] not in unique_list:
            unique_list.append( x['Reference_CIS']+x['title'])
            final.append(x)
    return final

def to_csv(list_of_dict,filename='analyse'):
    with open(filename+now+".csv", 'w', encoding='UTF8', newline='') as f:
            
            fieldnames = list(list_of_dict[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames,dialect='excel')
            writer.writeheader()
            writer.writerows(list_of_dict)   




path = 'WS2016/CIS_Qualys/'

list_file = os.scandir(path)
control_list_qualys = []
for item in list_file:
    if item.is_file():
        tree = ET.parse(path+item.name)
        root = tree.getroot()  
        # Parcours le CIS RHEL 7 de Qualys
        for s in root.iter('SECTION') :
            for c in s.iter('CONTROL') :
                    ref = {
                        'Reference_CIS' :c.find('REFERENCE_TEXT').text,
                        'CID' : c.find('ID').text
                    }
                    control_list_qualys.append(ref)
                    #print(ref)



path = 'WS2016/CIS_Tenable/'
list_file = os.scandir(path)
CIS_Tenable= []
for item in list_file:
    if item.is_file():
        data = open(path+item.name, "r").read()
        p = re.compile(r'(<custom_item>[^<>]+</custom_item>)')
        
        list_custom_item = p.findall(data)
        print(f' taille {len(list_custom_item)}')    
        for custom_item in list_custom_item:
            p = re.compile(r'description\s+:\s+\"(?P<Reference_CIS>[\d\.]*)\s+(?P<title>.*)\"')
            for m in p.finditer(custom_item):
                ref = m.groupdict()
            ref['source'] = item.name
            ref['item']=custom_item
            
            CIS_Tenable.append(ref) if 'title' in ref.keys() else print("error") 
            #print(ref)





mapping=[]
# Fait un mappage entre CID et CIS_ref pour les CIS_Ref commun entre Qualys et Tenable
i=0
for q in control_list_qualys:
    for t in CIS_Tenable:
        if q['Reference_CIS'] == t['Reference_CIS']:
            #print(f" CID {q['CID']} is in Tenable    {t['titre']}")
            item = {
                'CID' :q['CID'],
                'Reference_CIS' : t['Reference_CIS'],
                'title': t['title'],
                'source': t['source'],
                'item': t['item'],
            }
            mapping.append(item)
            i+=1
print(f'Nombre de réferences communes Qualys Tenable: {i} \ntaux de couverture = {round(i/len(control_list_qualys)*100)}%')

mapping = unique_list_dic(mapping)

#Récupere les CID de Qualys
path = 'WS2016/Custom_Qualys/'
tree = ET.parse(path+'ICDC_STD_SSI_Windows_Server_2016_2021_V4_20220601.xml')
root = tree.getroot()
qualys_custom = []
for s in root.iter('SECTION') :
    for c in s.iter('CONTROL') :
        qualys_custom.append({'CID' : c.find('ID').text})
i=0
final=[]
for q in unique(qualys_custom):
    exist=False
    for m in mapping:
        if m['CID']==q['CID']:
            i+=1
            item = {
                'CID' :q['CID'],
                'Reference_CIS' : m['Reference_CIS'] if 'Reference_CIS' in m.keys() else None,
                'title': m['title'] if 'title' in m.keys() else None,
                'source': m['source'] if 'source' in m.keys() else None,
                'item': m['item'] if 'item' in m.keys() else None
            }
            exist=True
            final.append(item)
    if not exist:
        item = {
                'CID' :q['CID'],
                'Reference_CIS' : '' ,
                'title': "Non trouvé" ,
                'source': None,
                'item': None,
            }
        final.append(item)

print(f'Nombre de controle Windows Server 2016 MS existant dans Tenable: {i} \ntaux de couverture = {round(i/len(final)*100)}%')


f = open("Windows_Server_2016"+now+".audit", "w")

for m in final:
    if m['item']!=None:
        f.write('\n')
        f.write(m['item'])
        f.write(f'\n#CUSTOM INFO\n#{m["CID"]} \n#{m["source"]} \n#{m["title"]}')
f.close()




#to_csv(unique(final),'list_final_win2016')
