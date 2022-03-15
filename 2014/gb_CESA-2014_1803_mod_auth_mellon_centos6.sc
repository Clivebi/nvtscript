if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882076" );
	script_version( "$Revision: 14058 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-11-06 06:19:00 +0100 (Thu, 06 Nov 2014)" );
	script_cve_id( "CVE-2014-8566", "CVE-2014-8567" );
	script_tag( name: "cvss_base", value: "9.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:C/A:C" );
	script_name( "CentOS Update for mod_auth_mellon CESA-2014:1803 centos6" );
	script_tag( name: "summary", value: "Check the version of mod_auth_mellon" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "mod_auth_mellon provides a SAML 2.0
authentication module for the Apache HTTP Server.

An information disclosure flaw was found in mod_auth_mellon's session
handling that could lead to sessions overlapping in memory. A remote
attacker could potentially use this flaw to obtain data from another user's
session. (CVE-2014-8566)

It was found that uninitialized data could be read when processing a user's
logout request. By attempting to log out, a user could possibly cause the
Apache HTTP Server to crash. (CVE-2014-8567)

Red Hat would like to thank the mod_auth_mellon team for reporting these
issues. Upstream acknowledges Matthew Slowe as the original reporter of
CVE-2014-8566.

All users of mod_auth_mellon are advised to upgrade to this updated
package, which contains a backported patch to correct these issues." );
	script_tag( name: "affected", value: "mod_auth_mellon on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2014:1803" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2014-November/020737.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "mod_auth_mellon", rpm: "mod_auth_mellon~0.8.0~3.el6_6", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

