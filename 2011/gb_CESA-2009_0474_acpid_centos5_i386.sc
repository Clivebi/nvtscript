if(description){
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2009-May/015873.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.880698" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_xref( name: "CESA", value: "2009:0474" );
	script_cve_id( "CVE-2009-0798" );
	script_name( "CentOS Update for acpid CESA-2009:0474 centos5 i386" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'acpid'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	script_tag( name: "affected", value: "acpid on CentOS 5" );
	script_tag( name: "insight", value: "acpid is a daemon that dispatches ACPI (Advanced Configuration and Power
  Interface) events to user-space programs.

  Anthony de Almeida Lopes of Outpost24 AB reported a denial of service flaw
  in the acpid daemon's error handling. If an attacker could exhaust the
  sockets open to acpid, the daemon would enter an infinite loop, consuming
  most CPU resources and preventing acpid from communicating with legitimate
  processes. (CVE-2009-0798)

  Users are advised to upgrade to this updated package, which contains a
  backported patch to correct this issue." );
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
	if(( res = isrpmvuln( pkg: "acpid", rpm: "acpid~1.0.4~7.el5_3.1", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

