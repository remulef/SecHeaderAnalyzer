import xml.etree.ElementTree as ET
import re
import os
import csv
import datetime
import collections
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


#Parsing QUALYS
path = 'RHEL7/CIS_Qualys/'

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

control_list_qualys_traite = []
for item in control_list_qualys:
    for ref in item['Reference_CIS'].split(', '):
        elem = {
                        'Reference_CIS' : ref,
                        'CID' : item['CID']
                    }
        control_list_qualys_traite.append(elem)




path = 'RHEL7/CIS_Tenable/'
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
                ref_tenable = m.groupdict()
            try:
                ref_tenable['source'] = item.name
                ref_tenable['item']=custom_item
                #ref['item']=custom_item if ref  in locals() else print("ko")
                CIS_Tenable.append(ref_tenable) if 'title' in ref_tenable.keys() else print("error")
            except Exception as e:
                print(e)
                pass
            
            #print(ref)



CIS_Tenable = unique_list_dic(CIS_Tenable)

d=collections.defaultdict(int)
for item in CIS_Tenable:
    d[item['Reference_CIS']]+=1

#trier
temp=0
CIS_Tenable_sorted = sorted(CIS_Tenable, key=lambda d: d['Reference_CIS'])

for item in CIS_Tenable_sorted:
    nb_occurence = d[item['Reference_CIS']]
    if nb_occurence>1:
            temp+=1
            item['Reference_CIS'] = item['Reference_CIS']+"."+chr(96+temp)
    if temp == nb_occurence:
        temp=0



mapping=[]
# Fait un mappage entre CID et CIS_ref pour les CIS_Ref commun entre Qualys et Tenable
i=0
for q in control_list_qualys_traite:
    for t in CIS_Tenable:
        if q['Reference_CIS'] == t['Reference_CIS']:
            #print(f" CID {q['CID']} is in Tenable    {t['titre']}")
            item = {
                'CID' :q['CID'],
                'Reference_CIS' : t['Reference_CIS'],
                'title': t['title'],
                'item': t['item'],
            }
            mapping.append(item)
            i+=1
print(f'Nombre de réferences communes Qualys Tenable: {i} \ntaux de couverture = {round(i/len(control_list_qualys)*100)}%')

mapping = unique_list_dic(mapping)

#Récupere les CID de Qualys
path = 'RHEL7/Custom_Qualys/'
tree = ET.parse(path+'ICDC_STD_SSI_Redhat_7_9_3_1_20220601.xml')
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
                'item': m['item'] if 'item' in m.keys() else None
            }
            exist=True
            final.append(item)
    if not exist:
        item = {
                'CID' :q['CID'],
                'Reference_CIS' : '' ,
                'title': "Non trouvé" ,
                'item': None,
            }
        final.append(item)

print(f'Nombre de controle Linux existant dans Tenable: {i} \ntaux de couverture = {round(i/len(final)*100)}%')


f = open("Windows_Server_2016"+now+".audit", "w")

for m in final:
    if m['item']!=None:
        f.write('\n')
        f.write(m['item'])
        f.write(f'\n#CUSTOM INFO\n#{m["CID"]} \n#{m["title"]}')
f.close()




#to_csv(unique(final),'list_final_win2016')
