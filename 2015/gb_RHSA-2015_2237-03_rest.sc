if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871507" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-20 06:27:11 +0100 (Fri, 20 Nov 2015)" );
	script_cve_id( "CVE-2015-2675" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for rest RHSA-2015:2237-03" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rest'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The rest library was designed to make it
easier to access web services that claim to be RESTful. A RESTful service should
have URLs that represent remote objects, which methods can then be called on.

It was found that the OAuth implementation in librest, a helper library for
RESTful services, incorrectly truncated the pointer returned by the
rest_proxy_call_get_url call. An attacker could use this flaw to crash an
application using the librest library. (CVE-2015-2675)

All users of rest are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
update, all applications using librest must be restarted for the update to
take effect." );
	script_tag( name: "affected", value: "rest on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2015:2237-03" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2015-November/msg00034.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "rest", rpm: "rest~0.7.92~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "rest-debuginfo", rpm: "rest-debuginfo~0.7.92~3.el7", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

