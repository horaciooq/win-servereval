#!/bin/python3
#https://stackoverflow.com/questions/39913847/is-there-a-way-to-compile-a-python-application-into-static-binary
from fileinput import filename
import os
from sys import stdout
import subprocess
import json
import platform
import socket
from datetime import datetime
from telnetlib import theNULL
import psutil
import wmi
import winreg
import logging
import base64

logging.basicConfig(filename='evalserver_error.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s')
directorio=os.getcwd()



def read_reg(hkey,camino,k):
	valor=""
	try:
		llave=winreg.OpenKeyEx(hkey, camino)
		valor=winreg.QueryValueEx(llave,k)
		if llave:
			winreg.CloseKey(llave)
	except Exception as e:
		logging.error(e)
	return valor[0]

def getBanner():
    print("[-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-]")
    print("[*]                                                         [*]")
    print("[*]       ooo.   .oPYo. B       .oPYo. .oPYo.      .oo      [*]")
    print("[*]       E  'B. B      B       B    B 8          .P 8      [*]")
    print("[*]       E   'B 'Yooo. B       B      'Yooo.    .P  8      [*]")
    print("[*]       E    B     '8 B       B          '8   oPooo8      [*]")
    print("[*]       E   .P      8 B       B    B      8  .P    8      [*]")
    print("[*]       Eooo'  'YooP' B       'YooP' 'YooP' .P     8      [*]")
    print("[*]---------------------------------------------------------[*]")
    print("[*]                       Ver 1.0                           [*]")
    print("[*]---------------------------------------------------------[*]")
    print("[*]     Este script te ayudara recolectar las evidencias    [*]")
    print("[*]     solicitadas en IEECO                                [*]")
    print("[*]                                                         [*]")
    print("[*]     Creado por: CSA EKT csa-ekt@totalsec.com.mx         [*]")
    print("[-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-][-]")
    print("")
    return ""

def getSOname():
    sysname=platform.system()
    return sysname 

def getHostName():
	Nombre=platform.node()
	return Nombre

def getDomain():
	fqdn = socket.getfqdn()
	return fqdn

def getSOVersion():
	version= platform.version()
	return version

def getDetalleSO():
	product_name=read_reg(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\Microsoft\Windows NT\CurrentVersion","ProductName")
	distro=platform.system()+ " "+ platform.release()+" "+ platform.win32_edition()
	return product_name

def getRol():
	Rol=""
	tecnologia=[]
	w=wmi.WMI()
	if installedfeatures:
		for u in installedfeatures:
			if "Web Server (IIS)" in u['name']:
				Rol="WEB"
				version=read_reg(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\InetStp\\","VersionString")
				tecnologia.append({"tecnologia":"IIS","version":version})
		del u

		for i in softwareinstalled:
			if "Database Engine Services" in i['nombre']:
				tecnologia.append({"tecnologia":i['nombre'],"version":i['version']})
				if Rol != "WEB":
					Rol="Base de Datos"
	else:
		logging.error("No se detectan caracteristicas de servidor")


	return {"rol":Rol,"tecs":tecnologia}

def getIPAddress():
	net_int=[]
	IPS=psutil.net_if_addrs()
	#print(IPS.keys)
	for key, value in IPS.items():
		for i in value:
			if i[0]==2:
				net_int.append({"nombre":key, "ip_address":i[1], "netmask":i[2], "broadcast":str(i[3])})
	return net_int

def getSalidaInternet():
    try:
        host = socket.gethostbyname("www.google.com")
        s = socket.create_connection((host, 80), 2)
        return True
    except:
        pass
    return False

def getCMDResult(cmd=[]):
	p=subprocess.Popen(cmd,stdout=subprocess.PIPE)
	output , err = p.communicate()
	return output
    
def getInstalledSoftware():
	software=[]
	p=wmi.WMI()
	for u in p.Win32_Product(["IdentifyingNumber","Caption","Version","InstallDate","InstallSource","Vendor"]):
		software.append({"identificador":u.IdentifyingNumber,"nombre":u.Caption,"version":u.Version,"fecha_instalacion":u.InstallDate,"localizacion":u.InstallSource,"vendor":u.Vendor})
	del u
	return software



def sanBytes(valor):
	#valor=str(valor).replace("b'","")
	valor=str(valor.decode(ascii)).strip()
	return valor

def encodestring(base64_bytes):
	base64_output=base64.b64encode(base64_bytes)
	return base64_output.decode('ascii')

def getScanInfo():
	version="1.0"
	scan_info={}
	user=os.getlogin()
	fecha=datetime.now()
	fecha=str(fecha.day) + "_" + str(fecha.month) + "_" + str(fecha.year) + "_" + str(fecha.hour) + "_" + str(fecha.minute) + "_" + str(fecha.second)    
	scan_info.update({"fecha_escaneo":fecha})
	scan_info.update({"usuario_ejecutor":user})
	scan_info.update({"version_script":version})
	scan_info.update({"tipo_de_servidor":""})
	scan_info.update({"tecnologia":""})
	scan_info.update({"version_tecnologia":[]})
	return scan_info

def getSysInfo():
	sysinfo={}
	sysinfo.update({"hostname":getHostName()})
	sysinfo.update({"dominio":getDomain()})
	sysinfo.update({"sistema_operativo":getSOname()})
	sysinfo.update({"detalleSO":str(getDetalleSO())})
	sysinfo.update({"releaseSO":str(getSOVersion())})
	sysinfo.update({"version":""})
	sysinfo.update({"net_interfaces":getIPAddress()})
	return sysinfo

def getSRV_17():
	resultado={}
	resultado.update({"id":"SRV-BAZ-CSA-17"})
	resultado.update({"nombre":"Asegurar que cuenta con versiones de tecnolog&iacute;a soportadas por el fabricante. S&oacute;lo se tomar&aacute; como valida la versi&oacute;n actual la versi&oacute;n actual - 1 o la versi&oacute;n LTS Long Term Support"})
	resultado.update({"descripcion":"Disminuye el riesgo de vulnerabilidades tipo 0-day vulnerabilidades recientes sin parches"})
	resultado.update({"remediacion":"Adjunta evidencia de las &uacute;ltimas versiones de sistema operativo utilizadas"})
	resultado.update({"estado":"no cumple"})
	resultado.update({"evidencia":[encodestring(getDetalleSO().encode('ascii'))]})
	return resultado

def getSRV_18():
	resultado={}
	resultado.update({"id":"SRV-BAZ-CSA-18"})
	resultado.update({"nombre":"Asegurar que no tiene salida a internet"})
	resultado.update({"descripcion":"Disminuye el riesgo de ataques de persistencia en los servidores"})
	resultado.update({"remediacion":"Deshabilitar la conexi&oacute;n a internet del equipo ya sea por firewall f&iacute;sico firewall local o declarando la no salida a internet en las rutas de la red. \n Ejecutar el comando ping 8.8.8.8 El resultado deber&aacute;n ser todos los paquetes perdidos"})
	if getSalidaInternet():
		resultado.update({"estado":"no cumple"})
	else:
		resultado.update({"estado":"cumple"})
	resultado.update({"evidencia":[encodestring(getCMDResult(["ping","8.8.8.8"]))]})
	return resultado

def getSRV_19():
	resultado={}
	resultado.update({"id":"SRV-BAZ-CSA-19"})
	resultado.update({"nombre":"Asegurar que solo se estan utilizando los puertos y servicios requeridos por el sistema"})
	resultado.update({"descripcion":"Protege la confidencialidad de la informaci&oacute;n de los datos de administraci&oacute;n del servidor."})
	resultado.update({"remediacion":"Deshabilitar / Desinstalar todos los servicios que son considerados inseguros y no son necesarios para el sistema. Por ejemplo:\n- TeamViewer\n- VNC y sus derivados\n- Telnet Server\n- Servicios de correo,\n- Etc. Cerrar todos los puertos no cifrados y / o no necesarios para el sistema. Por ejemplo- 5800- 5938- 25- 110- 143- 995- 993- 465- Etc. Enviar la salida de los siguientes comandos \nLinux:\nnetstat -noa \nsystemctl list-unit-files --type service \nWindows:\nnetstat -noa\ntasklist"})
	resultado.update({"estado":"no cumple"})
	resultado.update({"evidencia":[encodestring(getCMDResult(["netstat","-noa"])),encodestring(getCMDResult(["tasklist"]))]})
	return resultado

def getSRV_21():
	resultado={}
	resultado.update({"id":"SRV-BAZ-CSA-21"})
	resultado.update({"nombre":"Asegurar que cuenta con Antivirus Actualizado"})
	resultado.update({"descripcion":"Disminuye el riesgo de virus inform&aacute;tico."})
	resultado.update({"remediacion":"Instalar el software de antivirus corporativo\nEnviar una imagen del servicio de antivirus corriendo"})
	resultado.update({"estado":"no cumple"})
	resultado.update({"evidencia":[encodestring(getCMDResult(["wmic","product", "get","name"]))]})
	return resultado

def getResultados():	
	resultados=[getSRV_17(),getSRV_18(),getSRV_19(),getSRV_21()]
	return resultados

filename='resultado_' + getSysInfo()['hostname'] + '_' + getScanInfo()['fecha_escaneo'] 

def getjson():
	data={}
	data.update({"tipo":"Resultado_de_revision"})
	data.update({"informacion_escaneo":getScanInfo()})
	data.update({"informacion_sistema":getSysInfo()})
	data.update({"resultados":getResultados()})
	with open(directorio + "\\results\\" + filename + '.json','w') as outfile:
	    json.dump(data, outfile)
	print("Success")

try:	
	os.system('cls')
	getBanner()
	getjson()
	getCMDResult([str(directorio)+"\\moduloreporte.exe","-f",str(directorio)+"\\results\\" + str(filename) +".json","-o",str(directorio)+"\\results\\" + str(filename) + ".html"])  
except Exception as e:
    logging.error(e)
    print(e)