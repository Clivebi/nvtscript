if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871217" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-08-06 12:05:23 +0200 (Wed, 06 Aug 2014)" );
	script_cve_id( "CVE-2014-3490", "CVE-2012-0818" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "RedHat Update for resteasy-base RHSA-2014:1011-01" );
	script_tag( name: "affected", value: "resteasy-base on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "insight", value: "RESTEasy contains a JBoss project that provides frameworks to help build
RESTful Web Services and RESTful Java applications. It is a fully certified
and portable implementation of the JAX-RS specification.

It was found that the fix for CVE-2012-0818 was incomplete: external
parameter entities were not disabled when the
resteasy.document.expand.entity.references parameter was set to false.
A remote attacker able to send XML requests to a RESTEasy endpoint could
use this flaw to read files accessible to the user running the application
server, and potentially perform other more advanced XXE attacks.
(CVE-2014-3490)

This issue was discovered by David Jorm of Red Hat Product Security.

All resteasy-base users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:1011-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-August/msg00005.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'resteasy-base'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "resteasy-base-atom-provider", rpm: "resteasy-base-atom-provider~2.3.5~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "resteasy-base-jaxb-provider", rpm: "resteasy-base-jaxb-provider~2.3.5~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "resteasy-base-jaxrs", rpm: "resteasy-base-jaxrs~2.3.5~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "resteasy-base-jaxrs-api", rpm: "resteasy-base-jaxrs-api~2.3.5~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "resteasy-base-jettison-provider", rpm: "resteasy-base-jettison-provider~2.3.5~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

