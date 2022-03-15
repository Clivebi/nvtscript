if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.890994" );
	script_version( "2021-06-22T02:00:27+0000" );
	script_cve_id( "CVE-2017-5974", "CVE-2017-5975", "CVE-2017-5976", "CVE-2017-5978", "CVE-2017-5979", "CVE-2017-5980", "CVE-2017-5981" );
	script_name( "Debian LTS: Security Advisory for zziplib (DLA-994-1)" );
	script_tag( name: "last_modification", value: "2021-06-22 02:00:27 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-01-29 00:00:00 +0100 (Mon, 29 Jan 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-31 14:33:00 +0000 (Wed, 31 Mar 2021)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2017/06/msg00023.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB7" );
	script_tag( name: "affected", value: "zziplib on Debian Linux" );
	script_tag( name: "solution", value: "For Debian 7 'Wheezy', these problems have been fixed in version
0.13.56-1.1+deb7u1.

We recommend that you upgrade your zziplib packages." );
	script_tag( name: "summary", value: "CVE-2017-5974
Heap-based buffer overflow in the __zzip_get32 function in fetch.c
in zziplib allows remote attackers to cause a denial of service
(crash) via a crafted ZIP file.

CVE-2017-5975
Heap-based buffer overflow in the __zzip_get64 function in fetch.c
in zziplib allows remote attackers to cause a denial of service
(crash) via a crafted ZIP file.

CVE-2017-5976
Heap-based buffer overflow in the zzip_mem_entry_extra_block
function in memdisk.c in zziplib allows remote attackers to cause
a denial of service (crash) via a crafted ZIP file.

CVE-2017-5978
The zzip_mem_entry_new function in memdisk.c in zziplib allows
remote attackers to cause a denial of service (out-of-bounds
read and crash) via a crafted ZIP file.

CVE-2017-5979
The prescan_entry function in fseeko.c in zziplib allows remote
attackers to cause a denial of service (NULL pointer dereference
and crash) via a crafted ZIP file.

CVE-2017-5980
The zzip_mem_entry_new function in memdisk.c in zziplib allows
remote attackers to cause a denial of service (NULL pointer
dereference and crash) via a crafted ZIP file.

CVE-2017-5981
seeko.c in zziplib allows remote attackers to cause a denial of
service (assertion failure and crash) via a crafted ZIP file." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "libzzip-0-13", ver: "0.13.56-1.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "libzzip-dev", ver: "0.13.56-1.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if(!isnull( res = isdpkgvuln( pkg: "zziplib-bin", ver: "0.13.56-1.1+deb7u1", rls: "DEB7" ) )){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}

