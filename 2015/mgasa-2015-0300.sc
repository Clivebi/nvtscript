if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130078" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:42:27 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0300" );
	script_tag( name: "insight", value: "JSON error responses from the IPython notebook REST API contained URL parameters and were incorrectly reported as text/html instead of application/json. The error messages included some of these URL params, resulting in a cross site scripting attack (CVE-2015-4707). POST requests exposed via the IPython REST API are vulnerable to cross-site request forgery (CSRF). Web pages on different domains can make non-AJAX POST requests to known IPython URLs, and IPython will honor them. The user's browser will automatically send IPython cookies along with the requests. The response is blocked by the Same-Origin Policy, but the request isn't (CVE-2015-5607). The Mageia 5 package has been patched to fix these issues. The Mageia 4 package wasn't vulnerable to CVE-2015-4707, but it has been updated and patched to fix CVE-2015-5607." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0300.html" );
	script_cve_id( "CVE-2015-4707", "CVE-2015-5607" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0300" );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Mageia Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "MAGEIA5"){
	if(( res = isrpmvuln( pkg: "ipython", rpm: "ipython~2.3.0~2.2.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

