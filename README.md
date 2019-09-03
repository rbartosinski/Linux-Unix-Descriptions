# Linux/Unix - Descriptions about management and administrating
 Knowledge base about basics and standards in Linux/Unix management sys (RHEL, CentOS)


1. [Basic File System](#question1)
2. [Basic Storage Devices](#question2)
3. [LVM - Logical Volume Manager](#question3)
4. [NFS - Network File System](#question4)
5. [Samba](#question5)
6. [iSCSI - Internet Small Computer Systems Interface](#question6)
7. [Systemd/Init](#question7)
8. [Journald - Systemd log](#question8)
9. [Monitoring & Performance - CPU](#question9)
10. [Monitoring & Performance - RAM](#question10)
11. [Monitoring & Performance - Dyski](#question11)
13. [Pakiety, rpm, yum](#question13)
12. [Monitoring & Performance - Network](#question12)
12. [Monitoring & Performance - Network](#question12)
12. [Monitoring & Performance - Network](#question12)
12. [Monitoring & Performance - Network](#question12)
12. [Monitoring & Performance - Network](#question12)


<a name="question1"></a>
## 1. Basic File System

- Wszystko w Linuxach ma reprezentację w postaci pliku np. pliki; katalogi; urządzenia; network sockets (gniazda) itd.

- File system tree - Filesystem Hierarchy Standard (FHS) - definiuje standardy nazw; root - punkt poczatkowy.

`/`
    najwyższy poziom systemu plików

`/boot`
kernel, konfiguracja bootowania

`/etc`
pliki konfiguracji systemu

`/root`
home directory użytkownika root

`/media`
nośniki usuwalne DVD, CD, USB

`/mnt`
sieciowy system plikow

`/opt`
optional soft, add-on packages (pakiety dodatkowe)

`/usr`
programy, konfiguracje, nagłówki, biblioteki - user file system

`/usr/bin`
krytyczne pliki binarne dla systemu operacyjnego

`/usr/sbin`
pliki binarne administratora

`/var`
variable data, prints, maile, logi

`/dev`
device file system - show all conn devices

`/proc`
process file system - runnings state of the kernel, processes and memory info

`/sys`
system file system - pomaga zarządzać podłączonym hardware

`/tmp`
podręczne - nie powinno się zakładać że info w tmp będzie przechowywane pomiędzy uruchomieniami


    ls
    ll 
    ls /boot/
  
Urządzenia:
 
    ls /dev

np. lp0 - line printer 0 (first on the system)

    ll/dev/lp0
    ll/dev/disk
    
konfiguracje:

    ls /etc

id procesu:

    ps 
    ls /proc/1502
    more /proc/1502/io    (details about 1502)
    more /var/log/messages

absolute dirs vs relative dirs 

    ./ 
    ../ 
    ../../ 

    ln -s myFile myLink
    ll myLink
    ln myFile myLinkHard
    ll -i myLinkHard
    ll -i myFile

to samo ID pliku


Komendy: pliki

    touch 
    rm 
    mv 
    cat
    less/more
    head/tail       (glowa i ogon 10 pierwszych i ostatnich linii pliku)

Komendy: katalogi

    mkdir
    rm 
    rmdir 
    mv 
    ls - view content

find path expression np.
    
    find /home -name abxx
    
    
<a name="question2"></a>
## 2. Basic Storage Devices

Linux łączy się z urządzeniami za pomocą plików w systemie plików UNIX.

    ls -l /dev | grep sda

### Fdisk i Parted
Narzędzia do zarządzania urządzeniami, partycjami, systemami plików.

    parted
    fdisk -cu /dev/sda

Typ urządzenia we właściwościach pliku:

    brw----w--w         (pierwsze 'b' ozn. block device file)


informacje przekazywane do kernela jądra systemu jakich ma użyć urządzeń

- major device number

- minor device number

jeden dysk ma ten sam major dev number// ten sam scsi // ten sam driver

- minor - podział na partycje


### Partycje; format danych MBR i GPT
Partycje na jednym dysku MBR: do 16 miejsc; do 4 partycji primary na jednym urządzeniu dysku; pozostałe extended / logical

GUID/GPT dla wiekszych dysków, do 128 partycji + backup primary GPT na końcu urządzenia

MBR obsługuje do 2.2 TB

do GPT użyć parted (nie fdisk)


    fdisk -c /dev/xvda
    
      Command (m for help): n                                                                                                 
        Partition type                                                                                                             
        p   primary (0 primary, 0 extended, 4 free)                                                                             
        e   extended (container for logical partitions)                                                                      
      Select (default p): p                                                                                                   
        Partition number (1-4, default 1): 1                                                                                    
        First sector (2048-12582911, default 2048):                                                                             
        Last sector, +sectors or +size{K,M,G,T,P} (2048-12582911, default 12582911): +50M        
      Command (m for help): w           (na koniec do zatwierdzenia zmian)

    partprobe
    
    parted /dev/xvdf  
    parted
    (parted) mklabel gpt  
    (parted) unit MB                                                                             
    (parted) mkpart primary 0MB 50MB 
    rm 1 
    
W parted nie ma sieci bezpieczeństwa w postaci zatwierdzenia fdiskowego 'w'.


### System plików: xfs i ext

- Red Hat 7: xfs - skalowalny

- *przed Red Hat 7 system plików: ext np. Red Hat 6: ext4

- partycje raw - bez systemu plików

Stwórz system plików (formatowanie):

    mke2fs -t ext4 /dev/xvdf1

                                                                          
### Montowanie systemu plików:

        Tworzenie katalogu do montowania:
    78  mkdir /testmount                                                       
    79  sudo mkdir /testmount                                                                                                       
    81  ls -l /testmount  
    
        Montowanie:                                                                    
    85  mount -t ext4 /dev/xvdf1 /testmount                                                                   
    88  mount -l -t ext4                                                                                         
    89  umount /testmount/                                                                                       
        
        Montowanie próby:                                                                     
    91  sudo mount -t xfs /dev/xvdf1 /testmount    TYPE ERROR                                                              
    92  sudo mount -t ext4 /dev/xvdf1 /testmount     
    
        Sprawdzenie montowania na plikach:                                                                                                                                       
    94  sudo cp -r /var/log /testmount/                                                                          
    95  ls -l /testmount/                                                                                        
    96  ls -l /testmount/log                                                                                     
    97  umount /testmount/                                                                                                                                                                     
    99  ls -l /testmount/log                                                                                    
    100  mkdir -p 1/2/3                                                                                          
    101  cd 1/2/3                                                                                                
    102  pwd                                                                                                     
    103  touch ./newfile                                                                                         
    104  echo 'youp' > ./newfile                                                                                 
    105  cat ./newfile                                                                                           
    106  cd /                                                                                                    
    107  mount -t ext4 /dev/xvdf1 /1/2/3                                                                         
    108  sudo mount -t ext4 /dev/xvdf1 /1/2/3                                                                    
    109  sudo mount -t ext4 /dev/xvdf1 /1/2/3/                                                                   
    110  sudo mount -t ext4 /dev/xvdf1 /home/ec2-user/1/2/3                                                      
    111  ls -l /home/ec2-user/1/2/3                                                                              
    112  sudo umount /home/ec2-user/1/2/3/                                                                                                                  
    117  cd home/ec2-user/1/2/3/                                                                                 
    118  cat log                                                                                                 
    119  ls                                                                                                      
    120  cat newfile                                                                                             
    121  ls                                                                                                      


### Montowanie stałe (persistent mounting):

fstab - file system table

    /etc/fstab
    vi /etc/fstab

Sprawdzenie urządzeń i ich systemu plików:

    blkid
    lsblk --fs

### Super Block
- Super Block jest super ważny

- każdy system plików UNIX ma przynajmniej jeden Super Block

- bez super bloku nie ma dostępu do plików

- zawiera metadane dot sys plików ktorego dotyczy


    dumpe2fs /dev/xvdf1 | less 
    dumpe2fs /dev/xvdf1 | grep -i superblock  



### Inode - węzeł indexu

- tradycja systemów UNIX

- w sys plików każdy plik ma swój osobny inode, każdy dir także, każdy obiekt w systemie

- sys ma określoną liczbę wolnych inodeów które można zapisać


    ls -i /etc


### UUID (128 bit hash)
- lepiej pracować z UUID, a nie z plikami urządzeń na których są ustawione

- UUID nie zmieniają się po reboocie, pliki natomiast mogą się zmienić


    blkid

    e2label /dev/xvdf1 "nazwa nadana"

    fsck /dev/xvdf1 


Disk Free tool

    df -h 
    df -ih /// z inodeami
    df -Tih   ///typy sys plików i inody

    du -h /etc/

    lsblk                                                                                                                            
    mount -t xfs /dev/xvdf /mnt                                      
    
    Błąd UUID dwóch dysków montowanych takie samo (AWS):
    dmesg                                                                                                                                                          
    mount -o nouuid /dev/xvdf /mnt                                                                                                                                    
    mount -o nouuid,ro /dev/xvdf /mnt                                                                                                                              
    mount -t xfs -o nouuid /dev/xvdf /mnt                                                                                                                  
    mount -t xfs -o nouuid /dev/xvdf2 /mnt                                                                                                                
    cd /mnt/                                                                                                                                                 
    ls                                                                                                                                                  
    dmesg                                                                                                                                                   
    dmesg -T
    
<a name="question3"></a>
## 3. Logical Volume Manager  - LVM

### Physical Volumes, Volume Groups, Logical Volumes
Physical Volumes
    
    /dev/sda 200 GB + /dev/sdb 200GB

Volume Group VG  

    /dev/vg01 = 400GB

Logical Volumes LV   

    /dev/vg01/lv01 + /dev/vg01/lv02


if pvcreate command not foud:

    yum install -y lvm2


- good habit: działanie na partycjach, nie na samym urządzeniu


    pvcreate /dev/xvdf1

- good habit: jeden Physical Volume na jedno fizyczne urządzenie 


    pvremove /dev/xvdf1 /dev/xvdg1

label LVM metadane

    pvdisplay /dev/xvdf1
    pvdisplay /dev/xvdf1 -vvv



*nie jest tak łatwe jeśli PV jest cześcią Volume Group

    pvs


lvm2 - format zachowany (lvm1 dinozaury)


- PV - woda w basenie

- VG - ściany basenu i podłoga


    151  vgcreate vg_test /dev/xvdf1          
         out: Volume group "vg_test" successfully created  
                                                          
    151  vgdisplay vg_test 
    151  vgs 
    151  vgs -v
    151  vgdisplay vg_test                                                                                               
    151  vgs                                                                                                             
    152  vgs -v                                                                                                    
    
    151  vgcreate vg_test_pod --physicalextentsize 16 /dev/xvdg1                                                         
    155  vgs -v                                                                     
    156  vgremove vg_test_pod                                                                                            
    158  vgdisplay vg_test -v                                                                      
    159  vgextend vg_test /dev/xvdg1                                                                                     
    160  vgdisplay vg_test -v                                                                                     

### Physical Extents
- physical extents -> volume groups -> logical extents

- domyślnie PE jest stały i wynosi 4096 KB (4 MB);
  tzn. że x100 extents = 400 MB; x250 PE = 1 GB

- rozmiar PE można nadać tylko raz przy tworzeniu grupy VG jeśli nie jest domyślny (4096)

- nie można ich zmieniać w trakcie dla innych LVM działających w obrębie grupy


    lvcreate -L 1G -n lv_test vg_test             
        Logical volume "lv_test" created.                                                                                
    lvs                                
        LV      VG      Attr       LSize Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert                                 
        lv_test vg_test -wi-a----- 1.00g          
        
- `-wi-a------ wi` writable/alokacja dziedziczona; a active


    lvcreate -L 10M -n lv_new vg_test                                                     
        Rounding up size to full physical extent 12.00 MiB    (zaokrąglone do 12MB bo PE ma 4MB)                                                                
        Logical volume "lv_new" created. 
    
    ls -l /dev/vg_test                                                                  
        lrwxrwxrwx. 1 root root 7 Jul 25 10:11 lv_new -> ../dm-1                                                             
        lrwxrwxrwx. 1 root root 7 Jul 25 10:08 lv_test -> ../dm-0                                                            
    
    ls -l /dev | grep dm                                                                  
        crw-------. 1 root root     10,  61 Jul 25 08:44 cpu_dma_latency                                                     
        brw-rw----. 1 root disk    253,   0 Jul 25 10:08 dm-0                                                                
        brw-rw----. 1 root disk    253,   1 Jul 25 10:11 dm-1 

- `253` - numer urządzenia 253 mówi kernelowi, że to LVM i jakiego stera należy użyć
    
    
    mkfs -t ext4 /dev/vg_test/lv_test
    
    mkdir /lvm
    mount /dev/vg_test/lv_test /lvm 
    
    mount
    mount | grep lvm                                                                    
        /dev/mapper/vg_test-lv_test on /lvm type ext4 (rw,relatime,seclabel) 


- LVM - domyślny menedżer voluminu Linuxa

### Device Mapper

- kernel based framework for advanced block storage management

- mapuje block storage devices na inne block storage divices

Składa się z 3 warstw:
1. target devices,
2. mapping layer (table),
3. mapped devices

#### 1. target devices

    /dev/sda
    /dev/sdb

#### 2. mapping layer
 device mapper

#### 3. mapped devices
    /dev/mapper/<dev>


Device mapper - działa na poziomie jądra

lvm, dm-multipath  - na poziomie użytkownika

*połączeniem device mapper i lvm jest libdevmapper(api) - które wraz z dmsetup konfiguruje mapę użytkownika

linear mapped devices

### Zwiększanie LVM
      138  lvextend -L2G /dev/vg_test/lv1                                                                                     
      139  lvs                                                                                                                
      140  lvextend -L2G /dev/vg_test/lv_test                                                                                                                                                                                     
      144  lvs                                                                                                                
      145  lvextend -L +2G /dev/vg_test/lv_test                                                                                                                                                                                      
      147  lvs                                                                                                                
      148  resize2fs /dev/vg_test/lv_test 


### Zmniejszanie LVM
**backup danych wczesniej, inaczej operacja może okazać się niemiła w skutkach

Schemat:

1. *backup
1. unmount fs
2. check fs
3. reduce fs
4. reduce Logical Vol
5. re-check fs
6. re-mount fs

Komendy:

    umount /lvm                                                    
    e2fsck -f /dev/vg_test/lv_test                                               
    resize2fs /dev/vg_test/lv_test 1G                                                 
    lvreduce -L -2G vg_test/lv_test           
    e2fsck -f /dev/vg_test/lv_test                                           
    mount /dev/vg_test/lv_test /lvm


### LVM snapshots

- kopie woluminów

- działają tylko w środowisku LVM

- Space Efficient - nie konsumują wolnej przestrzeni dysku; tylko kiedy zostaną wprowadzone zmiany w woluminie źródła source vol

- źródło 200GB = snap 200GB



#### Point of Time (PiT)

-  dokładna kopia źródła w czasie którym została wykonana


    219  lvcreate -L 10M -s -n snap_lv_test /dev/vg_test/lv_test                            
    220  lvs                                                      
    221  lvdisplay vg_test/snap_lv_test                                     
    222  lvdisplay vg_test/lv_test                        
    223  cd /lvm                                   
    224  ls                                                          
    225  rm witajcie                                                           
    226  ls                                                          
    227  cd ..                                                          
    228  umount /lvm                                               
    229  lvconvert --merge vg_test/snap_lv_test

- na snapach można zapisywać/modyfikować je tak, że uruchomione mergem przeniosą zmodyfikowane dane


Uzycie do: 
1. PiT Recovery
2. Testowanie

- można operować manualnie - np wielkością snapów poprzez:


    lvextend

- lub automatycznie poprzez plik:
 
 
    /etc/lvm/lvm.conf


- nie pozwól się wypełnić snapom, bo zostaną zrzucone


    autoextend snapshot


- snapy nie są i nie powinny zastępować kopii zapasowych

- backupy sa przechowywane z dala od danych pierwotnych


### LVM Thin Provisioning

    252  lvcreate -L 100M tp_pool vg_test                                                                                   
    253  lvcreate -L 100M --thinpool tp_pool vg_test                                                                        
    254  lvs                                                                                                                
    255  lvcreate -V 1G --thin -n tp_lv_test vg_test                                                                        
    256  lvcreate -V 1G --thin -n tp_lv_test vg_test/tp_pool                                                                
    257  lvcreate -V 100G --thin -n tp2_lv_test vg_test/tp_pool                                                             
    258  lvs                                                                                                                
    259  lvdisplay vg_test/tp_lv_test
                                                                                           
    260  cd /lvm                                                                                                            
    261  ls                                                                                                                 
    262  cd ..                                                                                                              
    263  umount /lvm                                                                                                        
    264  cd ..                                                                                                              
    265  umount /lvm
                                                                                                           
    266  mkdir /small                                                                                                       
    267  mkdir /big                                                                                                         
    268  mkfs.ext4 /dev/vg_test/tp_lv_test                                                                                  
    269  lvdisplay vg_test/tp_lv_test                                                                                       
    270  lvdisplay vg_test/tp_pool                                                                                          
    271  mount /dev/vg_test/tp_lv_test /small                                                                               
    272  cp -r /etc /small                                                                                                  
    273  lvs                                                                                                                
    274  cp -r /sbin /small                                                                                                 
    275  lvs                                                                                                                
    276  mkfs.ext4 /dev/vg_test/tp_lv2_test                                                                                 
    277  mkfs.ext4 /dev/vg_test/tp2_lv_test


### mdraid - Linux RAID

- mdraid działa z partycjami


    yum install mdadm -y

    328  mdadm --examine /dev/xvdf /dev/xvdg                                                                                
    329  mdadm --examine /dev/xvdf1 /dev/xvdg1 ---- error
    331  mdadm --create /dev/md0 --level=mirror --raid-devices=2 /dev/xvdf1 /dev/xvdg1                                                                                                                                    
    334  ls -l /dev | grep md                                                                                               
    
    335  mdadm --examine /dev/xvdf1 /dev/xvdg1                                                                              
    336  mdadm --details /dev/md0                                                                                           
    337  mdadm --detail /dev/md0                                                                                            
    338  mkfs.ext4 /dev/md0                                                                                                 
    
    339  mkdir /raid                                                                                                        
    340  mount /dev/md0 /raid



<a name="question4"></a>
## 4. Network File System - NFS

- Linux może działać zarówno jako klient i jako serwer.

- linux może exportować lokalne katalogi do innych maszyn w sieci w tym samym czasie montując zdalne.

- Single export może dawać równoczesny dostęp do multiple clients.

- export (server) -> mount & re-export (server & client) -> mount (client)


<a name="question5"></a>
## 5. Samba

Porty samby do pracy: 137, 139, 445

### Konfiguracja serwera Samba:

1. Instalacja

        403  rpm -q samba                                                                                       
        404  yum install samba -y                                                                               
        405  rpm -q samba                                                                                       
        406  service smb status                                                                                 
        407  chkconfig --list smb                                                                               

2. Uruchomienie usługi    

        408  systemctl list-dependencies smb                                                                    
        409  systemctl list-dependencies                                                                        
        410  service smb start                                                                                  
        411  systemctl list-dependencies smb                                                                    
        412  service smb status                                                                                 
        413  smbclient -L localhost                                                                             

3. Diagnostyczna instalacja klienta

        414  yum install smbclient                                                                              
        415  mkdir /sambashare                                                                                  
        416  touch /sambashare/mission                                                                          

4. Plik testowy

        417  echo 'plik mission' > /sambashare/mission                                                   
        418  cat /sambashare/mission                                                                            
        419  ls -l /sambashare                                                                                  
        420  chown -R ec2-user:ec2-user /sambashare/                                                            
        421  ls -l /sambashare                                                                                  
        
5. Użytkownik samby
        
        422  cat /etc/passwd                                                                                    
        423  smbpasswd -a ec2-user                                                                              
        424  pdbedit -L                                                                                                                                                                       
        426  vi /etc/samba/smb.conf                                                                                                                  
        428  testparm                                                                                                                                                                           
        430  service smb reload                                                                                 
        431  systemctl reload smb.service                                                                       
        432  smbclient -L localhost -U ec2-user                                                                 
        433  cat /etc/services                                                                                  
        434  cat /etc/services | egrep '(microsoft)|(netbios)'                                                  
        
6. *Konfiguracja z firewallem/iptables
        
        435  vim /etc/sysconfig/iptables     
        436  ls -l /etc/sysconfig                                                                               
        437  vim /etc/sysconfig/samba                                                                           
        438  service iptables restart                                                                           

7. Konfiguracja zasad SELinux
        
        439  getenforce                                                                                         
        440  getsebool -a | grep samba                                                                          
        441  setsebool -P samba_export_all_rw on                                                                
        442  getsebool -a | grep samba                                                                          



### Konfiguracja klienta Samba:

    rpm -q samba-client                                                               
    yum install samba-client -y                                                                        
    smbclient -L //52.59.187.176/ -U ec2-user  
    smbclient -L sambaserver -U ec2-user  
    yum install cifs-utils 
    mount -t cifs //52.59.187.176/top-secret /smbmount          
    mount -t cifs -o user=ec2-user //52.59.187.176/top-secret /smbmount 

                                            
    cd /smbmount                                                                                                       
    ls                                                                                                                 
    vi mission                                                                                                         
                                                                                                      
    smbclient -L //52.59.187.176/ -U ec2-user                                                                          
    smbclient -L //52.59.187.176/                                                                                      
    cd ..                                                                                                              
    umount /smbmount                                                                                                   

    mount -t cifs //52.59.187.176/top-secret /smbmount                                                             
    mount -t cifs -o user=ec2-user //52.59.187.176/top-secret /smbmount                                                
    umount /smbmount     

<a name="question6"></a>
## 6. iSCSI

- block storage based; block-level protocol for sharing storage devices over IP network

- SAN technology for mass storage network; w odróżneiniu od NAS (block-level) technology jak NFS czy SMB (file-level)

- iSCSI initiator (host cpu & host ram memory) & iSCSI target (host cpu & host ram memory)


    468  yum search targetcli                                                                                               
    469  yum install targetcli -y                                                                                           
    470  cat /usr/lib/firewalld/services/iscsi-target.xml                                                                   
    471  firewall-cmd --add-service=iscsi-target --permanent                                                                
    472  systemctl start target                                                                                             
    473  systemctl enable target                                                                                            
    474  systemctl status target                                                                                            
    475  targetcli                                                                                                          
    476  ls -l /etc/target/  


https://www.linuxsysadmins.com/setup-an-iscsi-target-server-and-initiator-on-rhel-7-x-rhel-8/

https://www.linuxsysadmins.com/setup-an-iscsi-target-server-and-initiator-on-rhel-7-x-rhel-8/2/

_netdev - parametr dodawany w /etc/fstab kiedy sieć nie dziala nie bedzie montował urządzenia (automatyczne mountowanie)



nie jest ok jeśli wielu inicjatorów ma dostęp do pojedyńczej jednostki LUN

wielu inicjatorów uszkodzi LUN (iscsi target) mając dostęp jednocześnie

klaster może zapobiec takiemu uszkodzeniu


<a name="question7"></a>
## 7. Systemd/Init


### Start komputera:
1. bios/uefi
2. bootable device (mbr/gpt)
3. boot loader (linux: grub)
4. kernel
5. init - process id 1 - pid1

### Init:
- first 'user' process on the comp

- rodzic wszystkich innych procesów; nie ma procesu nadrzędnego

- odpowiedzialność kernela - organizowanie i uporządkowanie usług systemowych m.in. ssh, apache, syslog, mail, gnome desktop itd.

- **_przekazanie i przedstawienie użytkownikowi sprawnego użytecznego systemu_**


### initd (system V)
- użycie skryptów do inicjacji systemu

### systemd
- użycie gnizad do inicjacji systemu

- **_systemd - zmiemiennik initd, wykonuje wszystkie jego funkcje_**

- zacząć mniej i zacząć więcej równolegle

- *co trzeba zrobić żeby usługa x zadziałała: sieć musi być podłączona żeby uruchomić apache

#### journald

- process tracking - kontroluje grupy

- przełączenie pomiędzy levelami - init przekierowuje do systemd


    ls -la /sbin/init
    pstree -np          (np: numerical printout)

- potomkowie procesu - usługi systemowe


    ps -aux | grep ....

- po zastopowaniu i uruchomieniu od nowa otrzymała nowy process id, po każdym restarcie



### Systemd - architektura:

1) Units - jednostki - abstrakcja dla zasobów systemowych

2) Targets - cele - synonim poziomów działania 

3) Control groups


### 1) units 
- abstrakcja dla zasobów systemowych - zaimplementowana jako unit file system, jako plik, mają stan: 

     active/inactive; activating, deactivationg (mogą przechodzić między stanami),

- grupy unitów reprezentują stan systemu, enabled or disabled, etc/systemd/....,

- zależoności - dependency: before - jednostka jest potrzebna przed aktywacją innej/after - po

### Rodzaje unitów:

- service - starts and control daemons
- socket (gniazdo) - hermetyzacja, komunikacja międzyprocesorowa między systemd units, wywyołuje jednostki i wysyła przez gniazdo socket; socket-based activation; unit A może przesłać wiadomość do unit B za pomocą gniazda, w ten sposób systemd uruchamia unity asynchronicznie, równolegle,
- slice - kolekcja unitów w hierarchii - używane do zarządzania zasobami w slices and control groups
- scope- procesy uruchamiane zewnętrznie - uruchomienie np poprzez terminal
- snapshot - reprezentacja w czasie aktualnego stanu jednostek systemu, backup z określonymi usługami
- device - kernel devices - based on activation, as units
- mount - filesystem mount - zamontowane jednostki units są widoczne w /etc/fstab
- swap - units swap exchange partitions
- automount - file system mounted in the runtime
- path - file or dir
- timer - trggery aktywujące się w okreslonym czasie

#### Unit files:
- określone zachowanie i konfiguracja 
- raczej nie tworzymy ich od zera
- pochodzą z instalacji software (packages)
- żyją w lokalizacjach:

        /etc/systemd/system - user/admin created
        /var/run/systemd/system - runtime created
        /usr/lib/systemd/system - reinstalled with packages


#### Systemd - presedence (pierszeństwo)
- najmniejszy priorytet /usr/lib/

- największy  /etc/

- pierszeństwo przydziela systemd

- definiując unit można zastąpić jego domyślną konfigurację

- poprzez samo przenoszenie konfiguracji na wyższy priorytet umiejscowienia


    unit_name.type_extension
    httpd.service

[unit] - wewnątrz plików - basic description of the unit and dependecies

[services] - serv specific config

[install] - define what to do when want to enable/disable a unit

services from autostart with system start:

    systemctl enable/disable
        (symlink created or removed)


plik np. 

    /usr/lib/systemd/system/httpd.service:

-> targets - potrzebne inne usługi do uruchomienia usługi

sekcja service + Type=notify: powiadomienie systemd po zainicjowaniu/aktualizowaniu stanu

execstart = program binarny ktory będzie uruchomiony

Restart=on-failure

       39  systemctl enable httpd
      104  cd /usr/lib/systemd/system
      105  ls
      106  cd /var/run/systemd/system
      107  ls
      109  cat session-1.scope.d
      110  cd session-1.scope.d
      111  ls
      112  more 50-After-systemd-logind\\x2eservice.conf 
      113  more 50-Description.conf 
      114  cd ..
      115  ls
      116  w
      117  cd /etc/systemd/system
      118  ls
      119  grep http
      120  systemctl stop httpd
      121  systemctl disable httpd
      122  cd multi-user.target.wants/
      123  ls
      124  systemctl enable httpd
      125  ls
      126  grep htt
      127  ls grep http
      128  ls |  grep http
      129  systemctl start httpd
      130  vim /usr/lib/systemd/system/httpd.service 
      131  systemctl show httpd
      132  cp /usr/lib/systemd/system/httpd.service /etc/systemd/system
      133  ls
      134  cd..
      135  cd ...
      136  cd ..
      137  ls
      138  cd ..
      140  systemctl daemon-reload
      141  systemctl restart httpd
      142  systemctl status httpd
      146  vi /etc/systemd/system/httpd.service
      147  systemctl daemon-reload
      148  killall httpd
      149  ps -aux | grep http
      150  systemctl status httpd
      151  systemctl --type=socket
      152  systemctl


### 2) Targets - synonim poziomów działania 
- wcześniej były levele. 6 poziomów działania systemów, na których były uruchamane poszczegolne usługi, których wymagał system

- targets - grouping of units // grupuje unity i właściwe stany

- target definiuje stan systemu i które unity są uruchomione

#### named targets
predefiniowane zbiory unitów  w poszczególnych stanach
1. poweroff(0)
2. rescue(1) - single user mode
3. multi-user(2,3,4) - non-graphical
4. graphical(5)
5. reboot(6)

#### additional targets:
1. emergency - read only root
2. hibernate - saves state to disk & power is down
3. suspend - saves state in RAM & low power mode


na liście wszystkich targetów są też targety typou system wyłączony, tryb awaryjny, itd. 

    sytsemctl list-units --type target --all

Zmiana targetu:

    40  ls -lah multi-user.target.wants/
    41  systemctl set-default rescue
    41  systemctl set-default graphical
    42  systemctl get-default 
    43  ls -lah /etc/systemd/system/default.target


### 3) control groups

- cgroups; procesy są przypisane do cgroups

-  cgroups są organizowane przez:

    1. services - usługa to zbiór procesów uruchomionych przez systemd

    2. scope (zakres) to grupa porcesów uruchomionych zewnętrznie na systemd np przez terminal przez końcowego usera

    3. slices - grupa usług i zakresów

- informacje o wydajności środowiska (runtime performace information), możemy łatwo się dowiedzieć czy jednostka zużywa zasoby systemowe: dysk , cpu, ram, sieć.

- możemy zastosować reguły do ograniczenia spozycia zasobów, limit pamięci z której korzysta grupa, lub liczbę danych wejściowych do zapisania na dysku, czas oczekiwania procesora, zmienić priorytet

- dopasowywanie zasobów systemu do swoich potrzeb




<a name="question8"></a>
## 8. Journald - Systemd log

Usługa journald - kolekcja logów z kilku źródeł:
- kernel
- syslog
- sd_journal_print
- stdout and stderr z usług

domyślnie: runtime info only

dane dziennika ustrukturyzowane i indeksowane

    journalctl
    systemd-cgls
    systemd-cgtop 


**search globally for matches to the regular expression re, and print lines where they are found

    grep -i (ignore)
    grep -i mem
    systemctl show http | grep -i mem           (memory)

    vi /etc/systemd/system/httpd.service

nadpisanie pliku znajdującego się w usr/lib/systemd/system

przy ponownym uruchomieniu nie będzie działać

plik binarny journal

    mkdir -p /var/log/journal
    systemctl restart systemd-journald
    
    journalctl -f  (f - przytrzymanie; praca na innym terminalu i logi dot tego)
    journalctl -o verbose

danych odczytanych z dziennika verbose można kolejno użyć do zapytania dla dziennika

    journalctl _UID=1000
    journalctl _PID=1
    
    journalctl _SYSTEMD_UNIT=sshd.service
    journalctl -u firewalld
    
    journalctl --since "1 hour ago"
    journalctl --since "2 hours ago"
    journalctl --since "2 minutes ago"        (ew. error timeparse)
    
    journalctl --since 08:57:10
    
Manual journald:

    man systemd.journal-fields



<a name="question9"></a>
## 9. Monitoring & Performance- CPU


### Koncepy CPU

- Zasadniczy cel: **wykonywanie zadań**.

#### CPU memory topology:

- SMP - Symmetric Multi-Process

    - single memory space; procesy mogą przydzielać pamięć (allocate)
    - ograniczone możliwości skalowania
    - stała wydajność

- NUMA - Non-Uniform Memory Access

    - sekcje fizycznej pamięci są kontrolowane przez jeden lub wiele procesorów - tzw numa nodes - węzły
    - każdy węeł zarządza swoim rozmiarem pamięci
    - os zobaczy wszystkie procesory w ich węzłach numa, zobaczy także każdą pamięć
    - faworyzacja procesów na węźle lokalnym (zdalny wolniej)
    - poszukiwać pamięci zewnętrznej która może hamować wydajność
    - systemy wiedzą o NUMa


### Scheduler - wątki

- planuje zadania  - nazywane wątkami (threads)

- wątek - linuxowa abstrakcja dla jednostki pracy, zadanie do zrobienia

- scheduler zabiera wątki i umieszcza je w kolejce dostępu do procesora

- jeśli jest wiele procesorów, każdy bedzie miał swoją kolejkę

- nie ma tak, że kto pierwszy ten lepszy - są natomiast zasady które definiują w jaki sposób rzeczy są planowane

- Linux zawiera kilka wbudowanych zasad (policies)

- default scheduler - SCHED_OTHER/SCHED_NORMAL

- TIME SHARING SCHEDULING - wątek uzyska dostęp do procesora, na określony czas, wykona część pracy, a gdy czas z harmonogrammu się skończy wróci do harmonogramu całości, a sam wątek do kolejki ponownie - będzie się to powtarzać przez cały lifetime wątku próbującego uzyskać dostęp do procesora

- Zapobiega to obciążeniu precesora przez pojedyńczy wątek i np spaleniu procesora

    - *100 serwerów - nikt nie będzie tego robił ręcznie


- kilka kolejek z różnym priorytetem

- wątek i priorytetowość w linuxie nazwane **_niceness_** - dynamic priority list

- higher priority threads -> higher priority queue

- high priority queue - rozpatrywane w momencie kiedy procesor jest wolny do pracy


- numa aware software

- może być sytuacja zaplanowania wykonania wątku na innym węźle ze względu na rywalizację lub inne ograniczenia

**Koncepcja stanu procesu:**
- wątki wykonywane są w stanie uruchomionym - running
- wątki gotowe do wejścia na procesor będące w kolejce - runnable
- czekjace na zasób zewnętrzny - sleeping


### Na co zwrócić uwagę monitorując CPU
- very valuable performace meter
- percentage of: 60% czy będzie ok? jeśli dla userów to jest ok to jest ok. relatywizm
- zapewnienie, że nie będzie dużych odchyleń i skoków
- jeśli system spowalna znacząco obciążenie CPU może być za duże, np. 80% tym bardziej jeśli następują skoki nie do wykonania na 20%-ach pozostałego zasobu
- długość kolejek planowania - run queues

*Jeśli wątek czeka na dostęp do procesora, najprawdopodobniej program czeka i jego użytkownik także

### Średnia obciążenia - Load Average
- *znajdziesz np. w `top`, `w`, `uptime`, `proc` 


- krótkie skoki - short spikes - nie są złe

- Jeśli CPU wystrzeli na kilka sek lub minut, a następnie wróci do swojego stanu to ok, CPU był używany

- Jeśli skacze przez dłuższy okres czasu stojąc w miejscu może wskazywać na problem z aplikacją lub zasobami, wątkiem
warto się wówczas przyjżeć bliżej 

- Dobrze jest znać "baseline" i wiedzieć jakie zachowania są w normie i kiedy, przy jakim działaniu aplikacji czy scenariuszu 

- Long waits np:
    user
    I/O sieciowe, dyskowe, zewnętrzne
    - może być to problem systemowy nie zaś procesorowy


    lscpu

w lscpu info pochodzą z:

    cat /proc/cpuinfo


- Jeśli sys przestanie działać z racji wykonywania jakiegoś procesu, żeby podjąć działania naprawcze należało go będzie skillować

- *może być to to proces ze względów np biznesowych nie do skillowania



### Load Average vs. CPU usage

- load average - average length of the run queue for each of our cpu-s

- w narzędziu `top` jest load average w trzech kolumnach

- 1 - LA dla 1 minuty, 2 - dla 5 min; 3 - dla 15 min

- np w ciągu ostatnich 15 min było 1.42 procesa w kolejce do uruchomienia


`TOP` %CPUs:
1. us (user processes %), 
2. sy (system procs %), 
3. ni (nices procs), 
4. id (idle CPU - proces bezczynności), 
5. wa (waits, kiedy cpu czeka na external things jest tu generowana liczba), 
6. hi (przerwania programowe), 
7. st (stolen times, from hypervisor of VM)




<a name="question10"></a>
## 10. Monitoring & Performance - RAM

### Koncepty RAM

- Procesy w sys nie mają bezpośredniego dostępu do pamięci fizycznej

- Mają natomiast pamięć je reprezentującą - virtual memory

- Każdy proces ma swoją własną przestrzeń adresową (process address space)

- Zarówno fizyczne jak i virtualne pamięci są podzielone na strony (broken up into pages)

    - page jako jednostka alokacji dla pamięci fizycznej i wirtualnej

    - strona pamięci virtualnej może zostać odwzorowana na stronę pamięci fizycznej lub inny typ pamięci np na dysku twardym

### Memory Management  - Swapping

- SWAP - przeniesienie pamięci ram na dysk, based on its usage

- jesli nie będzie ona używana przez dłuższy czas można pobrać stronę (page) pamięci, zapisać na dysk, zapisać na dysk i przekazać pamięć innej aplikacji - SWAP OUT
- time base paging

- z punktu widzenia procesu adres pamięci virtualnej nigdy się nie zmienia

- fizyczny adres natomiast odwzorowuje się i jest aktualizowany w pamięci fizycznej, do bloków na dysku twardym gdzie zapisana jest strona 

- innym mechanizmem na swap out jest demand paging 

- manager pamięci zarządza tym przejściem (transition)

- page fault - jeśli adres próbuje uzyksać stronę zapisaną już na dysku, 

- manager pobierze stronę i umieści ja w pamięci fizycznej, zaktualizuje dane - SWAP IN


#### Excessing swapping - namierne swapowanie:
- ciągłe swapowanie in & out może oznaczać że w systemie brakuje pamięci
nadmierne swapowanie powoduje presję na subsystemie dyskowym, spowalniając wszystkie inne operacje

- dysk subsystem jest najwolniejszą cześcią komputera. pamięć główna działa w nanosekundach, dysk w mikro jesli to ssd, czy milisek jeśli to tradycyjny dysk magnetyczny

- można dostosować wielkość swapowania poprzez dostosowanie szybkości procesu 

- *** w bardzo specyficznych wymaganiach

https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/performance_tuning_guide/sect-red_hat_enterprise_linux-performance_tuning_guide-configuration_tools-configuring_system_memory_capacity#sect-Red_Hat_Enterprise_Linux-Performance_Tuning_Guide-Configuring_system_memory_capacity-Virtual_Memory_parameters


Monitoring pamięci:
- najwięksi konsumenci zarówno fizycznej jak i virtualnej
- kto swapuje i czy nadmiernie
- **file system cache


    cat /proc/meminfo | sort
    free
    free - m ///output in MB



`top`:
virt i res columns;
virtual address space;
można sprawdzić paging



    vmstat 1 100 (uruchom statystykę co sekundę 100x)
swap in i swap out: 
kolumna io 
BI Blocks In + BO blocks out


    yum install dstat



<a name="question11"></a>
## 11. Monitoring & Performance - Dyski


- Dysk słada się z sektorów (fizyczne) jednostki alokacji

- sektory przechowywały bity na fizycznym dysku

- block - fundamental unit of I/O z perspektywy systemu

- dane są zapisywane i odczytywane z bloków

- iNodes - obiekty systemu plików jak pliki czy katalogi dir

- kluczowe dla monitoringu jest:

    - przepustowość - bandwidth - szybkość transferu danych w MB/s lub GB/s - jak dużo danych można przenieść w danym okresie czasu
access latency - jak szybko transakcje dyskowe przechodzą od żadania do dostarczenia żadanych danych

- interconnections:
    - internal - zainstalowane na maszynie
    - external - dołączone 

- określone profile dla obydwu typów podłączeń


- file system

    - make backup + format na nowy fs + restore backup 


- podsystem dyskowy musi działać dobrze, w określony sposób


- ssd nie ma opóźnień spowodowanych fizycznym obracaniem się talerza dysku i dostęp do kolejnego i kolejnego bloku (magnetic)

    - sekwencyjny dostęp 

    - random dostęp - nie dane czytane sektor po sektorze

- 4KB - default block size w XFS

- dostosowanie np do baz danych np jeśli dane wprowadzane są zawsze w 16 KB moglibyśmy chcieć dostosować rozmair bloku
zminimalizowanie logical IOs (wejść/wyjść/sek) które system będzie musiał zrobić

    - nie ma znaczenia jeśli chodzi o zczytanie z dysku, ale o uruchomienie ścieżek dostarczenia do systemu

    - domyślnie dobrze jest trzymać się 4KB


- mount time options
disable access times:noatime;
wchodząc w interakcję z plikiem linuxowym zapisuje on czas tej reakcji w metadanych;
wylaczenie tej opcji moze poprawić wydajność;
ro - read only;


Wydajność:

- dysk - najwolniejsza część w komputerze; ssd nieco przyśpiesza ich działanie

- swapping spowalnia

- caching pomaga

- baseline

- wolne miejsce



    yum install iotop

    iotop

    blockdev --getbsz /dev/sda2
    


<a name="question12"></a>
## 12. Monitoring & Performance - Network

- network interface

- bandwidth (np b/s; GB/s)

- latency (ms)

- buffers

- queues (larger resources)


#### Proces przekazywania danych w sieci - Linux:


1. dane wchodzą do interfejsu sieciowego + internal buffer

    os przerywa proces interfejsu przekazując dane do

2. network stacka wewnątrz kernela + buffer

    decyzja o przekazaniu ramki którą odebrał: keep (forward) or discard; następnie 

3. socket queue

4. aplikacja



### Monitoring:

- saturation interface - nasycenie interfejsu (pojemność)
    - dodanie interfejsów w razie radzenia sobie lub zwiększenie przepustowości z 1 do 10 GB

- latency 

- nadmierne przerywanie (izolacja procesu i diagnozowanie w razie czego)
    - np przy iSCSI przy przenoszeniu pamięci blokowej przez sieć LAN przy wydajnych sys baz danych

- kolejkowanie w interfejsach

- zrzucanie pakietów (optymalizacja TCP)


    yum install iptraf-ng
    iptraf-ng



TCP sockets - both-directional; utility to investigating socket

    ss -t4 



- Ważne poznanie "baseline"

    - wiesz jak działają normalnie
    - znasz wzory
    - znasz prawidłowe zużycie pamięci dysku cpu itd
    - ochylenia od normy - deviations

- Testowanie nowego systemu i jego wydajności przed wdrożeniem na produkcję

    - overall benchmarking (sprawdzanie wydajności systemu jako całości)
    - isolated benchmarking


- Monitoring ważny - nie możesz podejmować decyzji bez danych

- `sysstat`
    - iostat, cifsiostat, nfsiostat
    - mpstat, pidstat
    - sar - system activity reporter
    - dstat
    - systat - możliwość raportowania info o wydajności

Info o działaniu:

    cat /etc/cron.d/sysstat

Dane przechowywane w plikach binarnych

`sadc` - system activity data collector

samo wpisanie komendy poniżej wygeneruje raport

    /usr/lib64/sa/sa2 -A
    
    vi /etc/sysconfig/sysstat


raport sar z `/etc/cron.d/sysstat`; otworzysz normalnie - jest tekstowy

`sa` są binarne


    sar -u              /// cpu utilization % with the time
    sar -q              /// load average
    sar -q -f sa01      /// -f file
    sar -q -1           /// minus 1 dzień
    sar -A              /// sar activity report
    
    sar -A | more       /// poruszanie strzałkami 
    
    sar -A -s 09:50:00
    sar -A -s 09:50:00 -e 10:10:00 (start + end)

    sadf -d | head
    sadf -d > out.csv ///-d jako dane arkusza kalkulacyjnego


- dstat


    yum install dstat
    
    dstat
    dstat --tcp
    dstat --all --tcp
    dstat -t --all --tcp


<a name="question13"></a>
## 13. Pakiety, rpm, yum


- Zależności i ich konfigurowanie było problematyczne kiedy nowe programy dociągało się i instalowało 

- czasami zależności było dużo


- rpm - redhat packet manager


    /usr/share/doc


rpm:
- pliki, foldery, biblioteki, skrypty, pliki binarne
- dokumentacje
- metadane
- wersjonowanie
- info o pakietach rpm w bazie danych systemu
- weryfikowalne
- nazewnictwo "szeregowe"

rpm manager:
- build - kompilacja źródła do binary rpm
- install
- query - zapytanie do bazy danych o zakres informacji metadanych
- verify - weryfikacja i porównanie pakietów zainstalowanych z innymi
- upgrade - aktualizacja lub instalacja jeśli pakiet nie jest zainstalowany
- freshen - aktualizacja tylko jesli pakiet jest zainstalowany
- erase - odinstalowanie


    rpm -qip nazwa_pakietu.rpm              / metadane z grubsza
    rpm -qlp nazwa_pakietu.rpm              / pliki w pakiecie
    rpm -qlp nazwa_pakietu.rpm | more
    rpm -K nazwa_pakietu.rpm                / zweryfikować rpm poprzez zgodność podpisu, suma MD5, pakiet nie będzie poprawnie zweryfikowany jeśli cokolwiek wewnątrz pakietu ulegnie zmianie      
    
    rpm -ivh nazwa_pakietu.rpm              / instalacja
    rpm -q  nazwa_pakietu.rpm               / czy jest zainstalowany
    rpm -qa                                 / wszystkie qa zainstalowane w systemie
    rpm -qf /etc/firewalld                  / zapytaj o plik (query file) i dane z której/jakiej paczki pochodzi?
    
    rpm -qi packet_output_name.rpm          / informacje z bazy systemu o rpm a nie jak poprzednio -qip z katalogu lokalnegow którym znajduje się paczka
    rpm -e mc                               / e: erase, po zakończeniu pracy na pakiecie
    rpm -U nazwa_pakietu.rpm                / upgrade
    rpm -Vv firewalld                       / co sie zmieniło w stosunku do pierwszej wersji
    
    rpm2cpio nazwa_pakietu.rpm | cpio       / przepuszczenie pakietu przez archiwum - jeśli pliki się zgubiły można je tam odnaleźć/odzyskać
    




### built own rpm packages

vault.centos.org


    cat /etc/centos-release

    rpm -qlp nazwa.rpm                      / podejrzyj pliki wewnątrz paczki

- jeśli jest wewnątrz plik 
    - .tar.xz - są to źródłowe pliki
    - .spec - specyfikacja budowania paczek


    rpm2cpio nazwa.rpm | cpio -id           / rozpakuje archiwum rpm
    tar -xf nazwa.tar.xf                    / rozpakuje plik tar do nowego dir


- komponenty do budowania własnych pakietów rpm


    yum group install "Development Tools"

    rpmbuild --rebuild nazwea_pakietu.rpm

- jeśli pojawai sie failed dependencies tzn. że trzeba zainstalować podane pakiety


    yum install ncurses-devel ......

- nie ma w tym katalogu gdzie tworzyliśmy tylko w głównym użytkownika 

- ***uważać na tworzenie paczek spod roota - ma duże możliwości także zmian na systemie


    ls -R rpmbuild                     / recursive ls
    
    yum info rpmdevtools

- umieszczenie plików w SOURCES i w SPEC: napisanie pliku w spec na podstawie templatki

- deployment tak stworznego pliku na innych maszynach



### YUM - Yellowdog Updater Management


    yum check-update
    yum update
    yum check-update
    
    yum group list
    yum group info "basic web server"
    yum group install "basic web server"
    
    
- update vs upgrade - usunięcie przestarzałych plików

    
        yum list tuned                                      / pokaże zainstalowane paczki
        yum search tuned
        yum provides top
        yum provides firewalld
        yum provides  ....
        
        yum list installed


yumdownloader procps-ng

pakiety które można przenieść do dowolnego komputera w naszym data center



#### Repozytoria

- Większość oprogramowania do sprawnego utrzymania systemów na repo producentów jak RH, centos

    - 3-rd parties - epel, rpmforge
    - własne


używać uwierzytelnionych repo

    /etc/yum.conf
    /var/log/yum.log


