if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131166" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-12-29 11:15:48 +0200 (Tue, 29 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0492" );
	script_tag( name: "insight", value: "Updated thunderbird packages fix security vulnerabilities: Several flaws were found in the processing of malformed web content. A web page containing malicious content could cause Thunderbird to crash or, potentially, execute arbitrary code with the privileges of the user running Thunderbird (CVE-2015-7201, CVE-2015-7205, CVE-2015-7210, CVE-2015-7212, CVE-2015-7213, CVE-2015-7222). A flaw was found in the way Thunderbird handled content using the 'data:' and 'view-source:' URIs. An attacker could use this flaw to bypass the same-origin policy and read data from cross-site URLs and local files (CVE-2015-7214)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0492.html" );
	script_cve_id( "CVE-2015-7201", "CVE-2015-7205", "CVE-2015-7212", "CVE-2015-7213", "CVE-2015-7214" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0492" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~38.5.0~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "thunderbird-l10n", rpm: "thunderbird-l10n~38.5.0~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

