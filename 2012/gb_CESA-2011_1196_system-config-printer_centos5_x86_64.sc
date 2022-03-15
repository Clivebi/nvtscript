if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2011-September/017992.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.881444" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-07-30 17:52:46 +0530 (Mon, 30 Jul 2012)" );
	script_cve_id( "CVE-2011-2899" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_xref( name: "CESA", value: "2011:1196" );
	script_name( "CentOS Update for system-config-printer CESA-2011:1196 centos5 x86_64" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'system-config-printer'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "system-config-printer on CentOS 5" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "insight", value: "system-config-printer is a print queue configuration tool with a graphical
  user interface.

  It was found that system-config-printer did not properly sanitize NetBIOS
  and workgroup names when searching for network printers. A remote attacker
  could use this flaw to execute arbitrary code with the privileges of the
  user running system-config-printer. (CVE-2011-2899)

  All users of system-config-printer are advised to upgrade to these updated
  packages, which contain a backported patch to resolve this issue. Running
  instances of system-config-printer must be restarted for this update to
  take effect." );
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
	if(( res = isrpmvuln( pkg: "system-config-printer", rpm: "system-config-printer~0.7.32.10~1.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "system-config-printer-libs", rpm: "system-config-printer-libs~0.7.32.10~1.el5_7.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

