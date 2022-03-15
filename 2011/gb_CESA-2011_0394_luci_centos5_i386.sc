if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-April/017419.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880497" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:0394" );
	script_cve_id( "CVE-2011-0720" );
	script_name( "CentOS Update for luci CESA-2011:0394 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'luci'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "luci on CentOS 5" );
	script_tag( name: "insight", value: "The conga packages provide a web-based administration tool for remote
  cluster and storage management.

  A privilege escalation flaw was found in luci, the Conga web-based
  administration application. A remote attacker could possibly use this flaw
  to obtain administrative access, allowing them to read, create, or modify
  the content of the luci application. (CVE-2011-0720)

  Users of Conga are advised to upgrade to these updated packages, which
  contain a backported patch to resolve this issue. After installing the
  updated packages, luci must be restarted ('service luci restart') for the
  update to take effect." );
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
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "luci", rpm: "luci~0.12.2~24.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "ricci", rpm: "ricci~0.12.2~24.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "conga", rpm: "conga~0.12.2~24.el5.centos.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

