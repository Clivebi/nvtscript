if(description){
	script_xref( name: "URL", value: "http://lists.mandriva.com/security-announce/2011-04/msg00017.php" );
	script_oid( "1.3.6.1.4.1.25623.1.0.831375" );
	script_version( "$Revision: 12381 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2011-04-19 07:58:39 +0200 (Tue, 19 Apr 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "MDVSA", value: "2011:073" );
	script_cve_id( "CVE-2011-0997" );
	script_name( "Mandriva Update for dhcp MDVSA-2011:073 (dhcp)" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dhcp'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Mandrake Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mandriva_mandrake_linux", "ssh/login/release",  "ssh/login/release=MNDK_(mes5|2010\\.1|2010\\.0|2009\\.0)" );
	script_tag( name: "affected", value: "dhcp on Mandriva Linux 2009.0,
  Mandriva Linux 2009.0/X86_64,
  Mandriva Linux 2010.0,
  Mandriva Linux 2010.0/X86_64,
  Mandriva Linux 2010.1,
  Mandriva Linux 2010.1/X86_64,
  Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64" );
	script_tag( name: "insight", value: "A vulnerability has been found and corrected in ISC DHCP:

  dhclient in ISC DHCP 3.0.x through 4.2.x before 4.2.1-P1, 3.1-ESV
  before 3.1-ESV-R1, and 4.1-ESV before 4.1-ESV-R2 allows remote
  attackers to execute arbitrary commands via shell metacharacters in
  a hostname obtained from a DHCP message (CVE-2011-0997).

  Additionally for Corporate Server 4 and Enterprise Server 5 ISC DHCP
  has been upgraded from the 3.0.7 version to the 4.1.2-P1 version
  which brings many enhancements such as better ipv6 support.

  Packages for 2009.0 are provided as of the Extended Maintenance
  Program. The updated packages have upgraded to the 4.1.2-P1 version and patched
  to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://store.mandriva.com/product_info.php?cPath=149&amp;amp;products_id=490" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MNDK_mes5"){
	if(( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.2~0.4mdvmes5.2", rls: "MNDK_mes5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.1"){
	if(( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.2~0.4mdv2010.2", rls: "MNDK_2010.1" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2010.0"){
	if(( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.2~0.4mdv2010.0", rls: "MNDK_2010.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "MNDK_2009.0"){
	if(( res = isrpmvuln( pkg: "dhcp-client", rpm: "dhcp-client~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-common", rpm: "dhcp-common~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-devel", rpm: "dhcp-devel~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-doc", rpm: "dhcp-doc~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-relay", rpm: "dhcp-relay~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp-server", rpm: "dhcp-server~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "dhcp", rpm: "dhcp~4.1.2~0.4mdv2009.0", rls: "MNDK_2009.0" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

