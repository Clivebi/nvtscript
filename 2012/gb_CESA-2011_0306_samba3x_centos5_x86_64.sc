if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017392.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881279" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:15:28 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-0719" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0306" );
	script_name( "CentOS Update for samba3x CESA-2011:0306 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba3x'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "samba3x on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A flaw was found in the way Samba handled file descriptors. If an attacker
  were able to open a large number of file descriptors on the Samba server,
  they could flip certain stack bits to '1' values, resulting in the Samba
  server (smbd) crashing. (CVE-2011-0719)

  Red Hat would like to thank the Samba team for reporting this issue.

  Users of Samba are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing this
  update, the smb service will be restarted automatically." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "samba3x", rpm: "samba3x~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-client", rpm: "samba3x-client~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-common", rpm: "samba3x-common~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-doc", rpm: "samba3x-doc~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-domainjoin-gui", rpm: "samba3x-domainjoin-gui~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-swat", rpm: "samba3x-swat~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind", rpm: "samba3x-winbind~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba3x-winbind-devel", rpm: "samba3x-winbind-devel~3.5.4~0.70.el5_6.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

