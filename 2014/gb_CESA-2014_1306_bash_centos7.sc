if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882032" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-10-01 16:59:55 +0530 (Wed, 01 Oct 2014)" );
	script_cve_id( "CVE-2014-7169", "CVE-2014-6271" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CentOS Update for bash CESA-2014:1306 centos7" );
	script_tag( name: "insight", value: "The GNU Bourne Again shell (Bash) is a shell and command language
interpreter compatible with the Bourne shell (sh). Bash is the default
shell for Red Hat Enterprise Linux.

It was found that the fix for CVE-2014-6271 was incomplete, and Bash still
allowed certain characters to be injected into other environments via
specially crafted environment variables. An attacker could potentially use
this flaw to override or bypass environment restrictions to execute shell
commands. Certain services and applications allow remote unauthenticated
attackers to provide environment variables, allowing them to exploit this
issue. (CVE-2014-7169)

Applications which directly create bash functions as environment variables
need to be made aware of changes to the way names are handled by this
update. For more information see the Knowledgebase article at the linked references.

Note: Docker users are advised to use 'yum update' within their containers,
and to commit the resulting changes.

For additional information on CVE-2014-6271 and CVE-2014-7169, refer to the
aforementioned Knowledgebase article.

All bash users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue." );
	script_tag( name: "affected", value: "bash on CentOS 7" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1306" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-September/020592.html" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/1200223" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'bash'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "bash", rpm: "bash~4.2.45~5.el7_0.4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "bash-doc", rpm: "bash-doc~4.2.45~5.el7_0.4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

