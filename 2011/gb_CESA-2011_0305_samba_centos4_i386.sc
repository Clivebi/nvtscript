if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-March/017260.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880474" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 06:45:55 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2011:0305" );
	script_cve_id( "CVE-2011-0719" );
	script_name( "CentOS Update for samba CESA-2011:0305 centos4 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS4" );
	script_tag( name: "affected", value: "samba on CentOS 4" );
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
	script_tag( name: "solution", value: "Please install the updated packages." );
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
if(release == "CentOS4"){
	if(( res = isrpmvuln( pkg: "samba", rpm: "samba~3.0.33~0.30.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-client", rpm: "samba-client~3.0.33~0.30.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-common", rpm: "samba-common~3.0.33~0.30.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "samba-swat", rpm: "samba-swat~3.0.33~0.30.el4", rls: "CentOS4" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
