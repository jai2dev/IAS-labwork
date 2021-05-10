import sys
import pandas as pd


class TCP:

	def __init__(self):
		pass


	def acl(self,path,s_ip,s_port,d_ip,d_port,i):
		i=i-1
		dataset = pd.read_excel(path,nrows=5)
		results=[]
		res = 0


		flag=1	

		if(str(dataset.iloc[i]["Source IP"])!="Any"):

			l1,l2 = s_ip.split('.'),str(dataset.iloc[i]["Source IP"]).split('.')

			

			for j in range(len(l1)):

				if(l2[j]!='*' and l2[j]!=l1[j]):

					flag=0

		if(str(dataset.iloc[i]["Destination IP"])!="Any"):

			l1,l2 = d_ip.split('.'),str(dataset.iloc[i]["Destination IP"]).split('.')

			for j in range(len(l1)):

				if(l2[j]!='*' and l2[j]!=l1[j]):

					flag=0

		if dataset.iloc[i]["Destination Port"]!="Any" and dataset.iloc[i]["Destination Port"]!=d_port or dataset.iloc[i]["Source Port"]!="Any" and dataset.iloc[i]["Source Port"]!=s_port:
			flag=0

		


		if flag==1 and dataset.iloc[i]["Action"]=="Allow" or flag==0 and dataset.iloc[i]["Action"]=="Deny" :

			res=1

		




		return "Allow"*(res==1)+"Deny"*(res!=1)
		# if(res==1):
		# 	return "Allow"
		# else:
		# 	return "Deny"


	def convert_to_address(self,hex_address):
		ans=""
		for i in range(len(hex_address)):

			a=int(hex_address[i],16)

			if(i!=0):

				ans=ans+"."+str(a)

			else:

				ans+=str(a)

		return ans

	def address(self,hex_address):
		ans=""
		for i in range(len(hex_address)):
			if(i!=0):
				ans=ans+"."+str(hex_address[i])
			else:
				ans+=str(hex_address[i])
		return ans

	def arp(self,packet):
		a = packet.split(' ')

		s_mac,d_mac=a[22:28],a[32:38]

		s_ip,d_ip=self.convert_to_address(a[28:32]),self.convert_to_address(a[38:42])

		print("IP adress of the Source: "+s_ip,'\n',"IP adress of the Destination: "+d_ip)
		
		print("MAC address of the Source: "+self.convert_to_address(s_mac),'\n',"MAC adress of the Destination: "+self.convert_to_address(d_mac))
		



	def packet(self,packet):
		a = packet.split(' ')

		d_mac_adress,s_mac_adress = a[:6],a[6:12]
		
		version_of_ethernet = a[12:14]

		if(version_of_ethernet[1]=='06'):
			arp(packet)

		ip_version_part=a[14:16]
		ip_version =ip_version_part[0][0]

		

		length_of_the_datagram,total_length = a[16:18],a[18:20]
		
		flag_fragment = a[20:22]
		time_to_live = a[22]
		protocol_field=a[23]
		protocol_number = int(protocol_field,16)
		header_checksum = a[24:26]

		s_ip_adress,d_ip_adress = self.convert_to_address(a[26:30]),self.convert_to_address(a[30:34])
		
		

		s_port_number,d_port_number = a[34:36],a[36:38]
		
		

		p="UDP"

		if protocol_number==6:

			p="TCP"
		
		print("\n Protocol "+p+"\n")

		print(" MAC address of the Source: "+self.address(s_mac_adress),'\n',"MAC adress of the Destination: "+self.address(d_mac_adress),end='\n\n')
		
		print(" Version of Ethernet: "+str(int(version_of_ethernet[0],16)) + "."+ str(int(version_of_ethernet[1],16)),end='\n')
		print(" IP Version: "+str(int(ip_version[0],16))+".0",end='\n\n')


		print(" Datagram length: "+str(int(str(length_of_the_datagram[0]+length_of_the_datagram[1]),16)),end='\n')
		print(" Total length: "+ str(int(str(total_length[0])+str(total_length[1]),16)),end='\n')
		print(" TTL(Time to Live): "+str(int(time_to_live,16)),end='\n')
		print(" Protocol Field: "+str(int(protocol_field,16)),'\n',"Protocol number: "+str(protocol_number),end='\n\n')

		print(" IP adress of the Source: "+s_ip_adress,'\n',"IP adress of the Destination: "+d_ip_adress,end='\n\n')
		


		print(" Port number of Source: "+ str(int( str( str(s_port_number[0])+str(s_port_number[1])),16)),'\n',"Port number of Destination: "+ str(int( str( str(d_port_number[0])+str(d_port_number[1])),16)),end='\n\n')
		

		d_port,s_port = int( str( str(d_port_number[0])+str(d_port_number[1])),16),int( str( str(s_port_number[0])+str(s_port_number[1])),16)
		




		return s_ip_adress,d_ip_adress,protocol_number,s_port,d_port








if __name__=='__main__':

	path=str(sys.argv[1])
	
	k=int(path[0])
	days_file = open(path,'r')
	
	data_dump = days_file.read()
	a = data_dump.split('\n')

	tcp=TCP()

	for i in a:
		if(i!=''):
			s_ip_adress,d_ip_adress,protocol_number,s_port,d_port=tcp.packet(i)
			a = tcp.acl('ACL-File.xlsx',s_ip_adress,s_port,d_ip_adress,d_port,k)
		print("\t\t\t\t Access : "+a,end='\n\n')