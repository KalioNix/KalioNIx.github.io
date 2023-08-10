---
title: "06. MBR"
date: 2023-04-09T14:58:47.119Z
categories: [Series, File system]
tags: ["forensic"]
---
## **MBR (Master Boot Record)**

---

MBR은 저장매체의 첫 번째 섹터(LBA 0)에 위치하는 512 bytes 크기의 영역이다. 처음 446 bytes는 부트 코드(Boot Code) 영역, 64 bytes는 파티션 테이블(Partition Table), 마지막 2 bytes는 시그니처를 나타낸다.

<br>

![](/images/853b475a-33ef-4fe9-8ecc-b165e7555cb0-image.png)

<br>

운영체제가 부팅 될 때 POST(Power On Self-Test) 과정을 마친 후 저장매체의 첫 번째 섹터를 호출하게 되는데 이 때 MBR의 부트 코드가 수행된다.

부트 코드(Boot Code)는 파티션 테이블에서 부팅 가능한 파티션을 찾아 해당 파티션의 부트 섹터를 호출해주는 역할을 한다.

만약, 부팅 가능한 파티션이 없을 경우에는 미리 정의된 에러 메시지를 출력한다.

<br>

다음 표는 MBR의 각 영역에 대한 세부적인 데이터구조를 나타낸다.

<table>
<thead>
  <tr>
    <th>범위 (Byte Range)</th>
    <th>설명 (Decription)</th>
    <th>크기 (Size)</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td> 0x0000 – 0x01BD</td>
    <td> Boot code</td>
    <td> 446 bytes</td>
  </tr>
  <tr>
    <td> 0x01BE – 0x01CD</td>
    <td> Partition table entry #1</td>
    <td> 16 bytes</td>
  </tr>
  <tr>
    <td> 0x01CE – 0x01DD</td>
    <td> Partition table entry #2</td>
    <td> 16 bytes</td>
  </tr>
  <tr>
    <td> 0x01DE – 0x01ED</td>
    <td> Partition table entry #3</td>
    <td> 16 bytes</td>
  </tr>
  <tr>
    <td> 0x01EE – 0x01FD</td>
    <td> Partition table entry #4</td>
    <td> 16 bytes</td>
  </tr>
  <tr>
    <td> 0x01FE – 0x01FF</td>
    <td> Signature (0x55AA)</td>
    <td> 2 bytes</td>
  </tr>
</tbody>
</table>

파티션 테이블은 각각 16 bytes씩 4개의 엔트리를 가지고 있다. 따라서 하나의 볼륨에서 부팅 가능한 주 파티션은 4개 밖에 생성할 수 없다.



<br>

### 파티션 테이블(Partition Table)

---

다음은 16bytes 파티션 테이블 엔트리의 세부적인 구조이다.

<table>
<thead>
  <tr>
    <th>범위 (Byte Range)</th>
    <th>설명 (Decription)</th>
    <th>크기 (Size)</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td> 0x00 – 0x00</td>
    <td> Boot Indicator<br>00 = do not use for booting<br>80 = system partition</td>
    <td> 1 byte</td>
  </tr>
  <tr>
    <td> 0x01 – 0x03</td>
    <td> Starting CHS address</td>
    <td> 3 bytes</td>
  </tr>
  <tr>
    <td> 0x04 – 0x04</td>
    <td> Partition type</td>
    <td> 1 byte</td>
  </tr>
  <tr>
    <td> 0x05 – 0x07</td>
    <td> Ending CHS address</td>
    <td> 3 bytes</td>
  </tr>
  <tr>
    <td> 0x08 – 0x0B</td>
    <td> Starting LBA address</td>
    <td> 4 bytes</td>
  </tr>
  <tr>
    <td> 0x0C – 0x0F</td>
    <td> Total sectors</td>
    <td> 4 bytes</td>
  </tr>
</tbody>
</table>

부트 식별자(Boot Indicator)는 해당 파티션이 부팅 가능한 파티션인지를 나타낸다. 0x80을 가질 경우 부팅 가능한 파티션을 나타내고, 0x00을 가질 경우 부팅이 가능하지 않은 파티션을 나타낸다.

그리고 CHS 주소 값이 나오는데 현재는 대부분 LBA 모드를 사용하므로 사용되지 않고 있다. 그 다음으로 해당 파티션의 시작 위치를 가리키는 LBA 주소 값과 파티션 전체의 섹터 수가 나온다. CHS와 다르게 LBA 주소의 마지막을 표시하지 않는 이유는 시작 주소에 섹터의 크기를 더하면 마지막 주소를 알 수 있기 때문이다.

파티션 유형(partition type)은 파티션에 포함된 파일 시스템을 지정한다. System ID와 Partition Type으로 구분하는 경우도 있지만 여기서는 파티션 타입으로 모두 정의한다.

<table>
<thead>
  <tr>
    <th>16진수</th>
    <th>설명 (Description)</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td> 00h</td>
    <td> Empty</td>
  </tr>
  <tr>
    <td> 01h</td>
    <td> DOS 12-bit FAT</td>
  </tr>
  <tr>
    <td> 02h</td>
    <td> XENIX root file system</td>
  </tr>
  <tr>
    <td> 03h</td>
    <td> XENIX /usr file system (obsolete)</td>
  </tr>
  <tr>
    <td> 04h</td>
    <td> DOS 16-bit FAT (up to 32M)</td>
  </tr>
  <tr>
    <td> 05h</td>
    <td> DOS 3.3+ extended partition</td>
  </tr>
  <tr>
    <td> 06h</td>
    <td> DOS 3.31+ Large File System (16-bit FAT, over 32M)</td>
  </tr>
  <tr>
    <td> 07h</td>
    <td> Advanced Unix</td>
  </tr>
  <tr>
    <td> 07h</td>
    <td> exFAT</td>
  </tr>
  <tr>
    <td> 07h</td>
    <td> OS/2 HPFS</td>
  </tr>
  <tr>
    <td> 07h</td>
    <td> Windows NT NTFS</td>
  </tr>
  <tr>
    <td> 08h</td>
    <td> OS/2 (v1.0-1.3 only)</td>
  </tr>
  <tr>
    <td> 08h</td>
    <td> AIX bootable partition, SplitDrive</td>
  </tr>
  <tr>
    <td> 08h</td>
    <td> Commodore Dos</td>
  </tr>
  <tr>
    <td> 08h</td>
    <td> DELL partition spanning multiple drives</td>
  </tr>
  <tr>
    <td> 09h</td>
    <td> AIX data partition</td>
  </tr>
  <tr>
    <td> 0Ah</td>
    <td> OPUS</td>
  </tr>
  <tr>
    <td> 0Ah</td>
    <td> Coherent swap partition</td>
  </tr>
  <tr>
    <td> 0Ah</td>
    <td> OS/2 Boot Manager</td>
  </tr>
  <tr>
    <td> 0Bh</td>
    <td> Windows 95 with 32-bit FAT</td>
  </tr>
  <tr>
    <td> 0Ch</td>
    <td> Windows 95 with 32-bit FAT (using LBA-mode INT 13 extensions)</td>
  </tr>
  <tr>
    <td> 0Eh</td>
    <td> VFAT logical-block-addressable VFAT (same as 06h but using LBA)</td>
  </tr>
  <tr>
    <td> 0Fh</td>
    <td> Extended LBA partition (same as 05h but using LBA)</td>
  </tr>
  <tr>
    <td> 10h</td>
    <td> OPUS</td>
  </tr>
  <tr>
    <td> 11h</td>
    <td> FAT12 OS/2 Boot Manager hidden 12-bit FAT partition</td>
  </tr>
  <tr>
    <td> 12h</td>
    <td> Compaq Diagnostics partition</td>
  </tr>
  <tr>
    <td> 14h</td>
    <td> FAT16 OS/2 Boot Manager hidden sub-32M 16-bit FAT partition</td>
  </tr>
  <tr>
    <td> 16h</td>
    <td> FAT16 OS/2 Boot Manager hidden over-32M 16-bit FAT partition</td>
  </tr>
  <tr>
    <td> 17h</td>
    <td> OS/2 Boot Manager hidden HPFS partition</td>
  </tr>
  <tr>
    <td> 17h</td>
    <td> hidden NTFS partition</td>
  </tr>
  <tr>
    <td> 18h</td>
    <td> ASTSuspend AST special Windows swap file (“Zoro-Volt Suspend” partition)</td>
  </tr>
  <tr>
    <td> 19h</td>
    <td> Willowtech Willowtech Photon coS</td>
  </tr>
  <tr>
    <td> 1Bh</td>
    <td> Windows hidden Windows95 FAT32 partition</td>
  </tr>
  <tr>
    <td> 1Ch</td>
    <td> Windows hidden Windows 95 FAT32 partition (LBA-mode)</td>
  </tr>
  <tr>
    <td> 1Eh</td>
    <td> Windows hidden LBA VFAT partition</td>
  </tr>
  <tr>
    <td> 20h</td>
    <td> Willowsoft Overture File System (OFS1)</td>
  </tr>
  <tr>
    <td> 21h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 21h</td>
    <td> FSo2</td>
  </tr>
  <tr>
    <td> 23h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 24h</td>
    <td> NEC MS-DOS 3.x</td>
  </tr>
  <tr>
    <td> 26h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 31h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 33h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 34h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 36h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 38h</td>
    <td> Theos</td>
  </tr>
  <tr>
    <td> 3Ch</td>
    <td> PowerQuest PartitionMagic recovery partition</td>
  </tr>
  <tr>
    <td> 40h</td>
    <td> VENIX 80286</td>
  </tr>
  <tr>
    <td> 41h</td>
    <td> Personal RISC Boot</td>
  </tr>
  <tr>
    <td> 41h</td>
    <td> PowerPC boot partition</td>
  </tr>
  <tr>
    <td> 42h</td>
    <td> SFS(Secure File System) by Peter Gutmann</td>
  </tr>
  <tr>
    <td> 45h</td>
    <td> EUMEL/Elan</td>
  </tr>
  <tr>
    <td> 46h</td>
    <td> EUMEL/Elan</td>
  </tr>
  <tr>
    <td> 47h</td>
    <td> EUMEL/Elan</td>
  </tr>
  <tr>
    <td> 48h</td>
    <td> EUMEL/Elan</td>
  </tr>
  <tr>
    <td> 4Fh</td>
    <td> Obron boot/data partition</td>
  </tr>
  <tr>
    <td> 50h</td>
    <td> OnTrack Disk Manager, read-only partition</td>
  </tr>
  <tr>
    <td> 51h</td>
    <td> OnTrack Disk Manager, read/write partition</td>
  </tr>
  <tr>
    <td> 51h</td>
    <td> NOVELL</td>
  </tr>
  <tr>
    <td> 52h</td>
    <td> CP/M</td>
  </tr>
  <tr>
    <td> 52h</td>
    <td> Microport System V/386</td>
  </tr>
  <tr>
    <td> 53h</td>
    <td> OnTrack Disk Manager, write-only partition</td>
  </tr>
  <tr>
    <td> 54h</td>
    <td> OnTrack Disk Manager (DDO)</td>
  </tr>
  <tr>
    <td> 55h</td>
    <td> EZ-Drive (see also INT 13/AH=FFh “EZ-Drive”)</td>
  </tr>
  <tr>
    <td> 56h</td>
    <td> GoldenBow VFeature</td>
  </tr>
  <tr>
    <td> 5Ch</td>
    <td> Priam EDISK</td>
  </tr>
  <tr>
    <td> 61h</td>
    <td> SpeedStor</td>
  </tr>
  <tr>
    <td> 63h</td>
    <td> Unix SysV/386, 386/ix</td>
  </tr>
  <tr>
    <td> 63h</td>
    <td> Mach, MtXinu BSD 4.3 on Mach</td>
  </tr>
  <tr>
    <td> 63h</td>
    <td> GNU-HURD</td>
  </tr>
  <tr>
    <td> 64h</td>
    <td> Novell Netware 286</td>
  </tr>
  <tr>
    <td> 64h</td>
    <td> SpeedStore</td>
  </tr>
  <tr>
    <td> 65h</td>
    <td> Novell NetWare (3.11)</td>
  </tr>
  <tr>
    <td> 67h</td>
    <td> Novell</td>
  </tr>
  <tr>
    <td> 68h</td>
    <td> Novell</td>
  </tr>
  <tr>
    <td> 69h</td>
    <td> Novell NSS Volume</td>
  </tr>
  <tr>
    <td> 70h</td>
    <td> DiskSecure Multi-Boot</td>
  </tr>
  <tr>
    <td> 71h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 73h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 74h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 75h</td>
    <td> PC/IX</td>
  </tr>
  <tr>
    <td> 76h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> 7Eh</td>
    <td> F.I.X</td>
  </tr>
  <tr>
    <td> 80h</td>
    <td> Minix v1.1 – 1.4a</td>
  </tr>
  <tr>
    <td> 81h</td>
    <td> Minix v1.4b+</td>
  </tr>
  <tr>
    <td> 81h</td>
    <td> Linux</td>
  </tr>
  <tr>
    <td> 81h</td>
    <td> Mitac Advanced Disk Manager</td>
  </tr>
  <tr>
    <td> 82h</td>
    <td> Linux Swap partition</td>
  </tr>
  <tr>
    <td> 82h</td>
    <td> Prime</td>
  </tr>
  <tr>
    <td> 82h</td>
    <td> Solaris (Unix)</td>
  </tr>
  <tr>
    <td> 83h</td>
    <td> Linux native file system (ex2fs/xiafs)</td>
  </tr>
  <tr>
    <td> 84h</td>
    <td> DOS OS/2-renumbered type 04h partition (hiding DOS C: drive)</td>
  </tr>
  <tr>
    <td> 85h</td>
    <td> Linux EXT</td>
  </tr>
  <tr>
    <td> 86h</td>
    <td> FAT16 volume/stripe set (Windows NT)</td>
  </tr>
  <tr>
    <td> 87h</td>
    <td> HPFS Fault-Tolerant mirrored partition</td>
  </tr>
  <tr>
    <td> 87h</td>
    <td> NTFS volume/stripe set</td>
  </tr>
  <tr>
    <td> 93h</td>
    <td> Amoeba file system</td>
  </tr>
  <tr>
    <td> 94h</td>
    <td> Amoeba bad block table</td>
  </tr>
  <tr>
    <td> 98h</td>
    <td> Datalight ROM-DOS SuperBoot</td>
  </tr>
  <tr>
    <td> 99h</td>
    <td> Mylex EISA SCSI</td>
  </tr>
  <tr>
    <td> A0h</td>
    <td> Phoenix NoteBIOS Power Management “Save-to-Disk” partition</td>
  </tr>
  <tr>
    <td> A1h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> A3h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> A4h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> A5h</td>
    <td> FreeBSD, BSD/386</td>
  </tr>
  <tr>
    <td> A6h</td>
    <td> OpenBSD</td>
  </tr>
  <tr>
    <td> A9h</td>
    <td> NetBSD</td>
  </tr>
  <tr>
    <td> B1h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> B3h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> B4h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> B6h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> B6h</td>
    <td> Windows NT mirror set (master), FAT16 file system</td>
  </tr>
  <tr>
    <td> B7h</td>
    <td> BSDI file system (secondarily swap)</td>
  </tr>
  <tr>
    <td> B7h</td>
    <td> Windows NT mirror set (master), NTFS file system</td>
  </tr>
  <tr>
    <td> B8h</td>
    <td> BSDI swap partition (secondarily file system)</td>
  </tr>
  <tr>
    <td> BEh</td>
    <td> Solaris boot partition</td>
  </tr>
  <tr>
    <td> C0h</td>
    <td> CTOS</td>
  </tr>
  <tr>
    <td> C0h</td>
    <td> DR-DOS/Novell DOS secured partition</td>
  </tr>
  <tr>
    <td> C1h</td>
    <td> DR-DOS6.0 LOGIN.EXE-secured 12-bit FAT partition</td>
  </tr>
  <tr>
    <td> C4h</td>
    <td> DR-DOS6.0 LOGIN.EXE-secured 16-bit FAT partition</td>
  </tr>
  <tr>
    <td> C6h</td>
    <td> DR-DOS6.0 LOGIN.EXE-secured 12-bit Huge partition</td>
  </tr>
  <tr>
    <td> C6h</td>
    <td> corrupted FAT16 volume/stripe set (Windows NT)</td>
  </tr>
  <tr>
    <td> C6h</td>
    <td> Windows NT mirror set (slave), FAT16 file system</td>
  </tr>
  <tr>
    <td> C7h</td>
    <td> Syurinx Boot</td>
  </tr>
  <tr>
    <td> C7h</td>
    <td> corrupted NTFS volume/stripe set</td>
  </tr>
  <tr>
    <td> C7h</td>
    <td> Windows NT mirror set (slave), NTFS file system</td>
  </tr>
  <tr>
    <td> CBh</td>
    <td> DR-DOS/OpenDOS secured FAT32</td>
  </tr>
  <tr>
    <td> CCh</td>
    <td> DR-DOS secured FAT32 (LBA)</td>
  </tr>
  <tr>
    <td> CEh</td>
    <td> DR-DOS secured FAT16 (LBA)</td>
  </tr>
  <tr>
    <td> D0h</td>
    <td> Multiuser DOS secured FAT12</td>
  </tr>
  <tr>
    <td> D1h</td>
    <td> Old Multiuser DOS secured FAT12</td>
  </tr>
  <tr>
    <td> D4h</td>
    <td> Old Multiuser DOS secured FAT16 (&lt;=32M)</td>
  </tr>
  <tr>
    <td> D5h</td>
    <td> Old Multiuser DOS secured extended partition</td>
  </tr>
  <tr>
    <td> D6h</td>
    <td> Old Multiuser DOS secured FAT16 (&gt;32M)</td>
  </tr>
  <tr>
    <td> D8h</td>
    <td> CP/M-86</td>
  </tr>
  <tr>
    <td> DBh</td>
    <td> Concurrent CP/M, Concurrent DOS</td>
  </tr>
  <tr>
    <td> DBh</td>
    <td> CTOS (Convergent Technologies OS)</td>
  </tr>
  <tr>
    <td> E1h</td>
    <td> SpeedStor 12-bit FAT extended partition</td>
  </tr>
  <tr>
    <td> E2h</td>
    <td> DOS read-only (Florian Painke’s XFDISK 1.0.4)</td>
  </tr>
  <tr>
    <td> E3h</td>
    <td> DOS read-only</td>
  </tr>
  <tr>
    <td> E3h</td>
    <td> Storage Dimensions</td>
  </tr>
  <tr>
    <td> E4h</td>
    <td> SpeedStor 16-bit FAT extended partition</td>
  </tr>
  <tr>
    <td> E5h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> E6h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> EBh</td>
    <td> BeOS BFS (BFS1)</td>
  </tr>
  <tr>
    <td> F1h</td>
    <td> Storage Dimensions</td>
  </tr>
  <tr>
    <td> F2h</td>
    <td> DOS 3.3+ secondary partition</td>
  </tr>
  <tr>
    <td> F3h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> F4h</td>
    <td> SpeedStor</td>
  </tr>
  <tr>
    <td> F4h</td>
    <td> Storage Dimensions</td>
  </tr>
  <tr>
    <td> F5h</td>
    <td> Prologue</td>
  </tr>
  <tr>
    <td> F6h</td>
    <td> [reserved] officially listed as reserved</td>
  </tr>
  <tr>
    <td> FBh</td>
    <td> VMware partition</td>
  </tr>
  <tr>
    <td> FEh</td>
    <td> LANstep</td>
  </tr>
  <tr>
    <td> FEh</td>
    <td> IBM PS/2 IML (Initial Microcode Load) partition</td>
  </tr>
  <tr>
    <td> FFh</td>
    <td> Xenix bad block table</td>
  </tr>
  <tr>
    <td> FMh</td>
    <td> VMware raw partition</td>
  </tr>
</tbody>
</table>


