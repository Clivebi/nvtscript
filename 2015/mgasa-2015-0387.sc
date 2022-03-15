if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.130006" );
	script_version( "2020-08-04T08:27:56+0000" );
	script_tag( name: "creation_date", value: "2015-10-15 10:41:24 +0300 (Thu, 15 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-08-04 08:27:56 +0000 (Tue, 04 Aug 2020)" );
	script_name( "Mageia Linux Local Check: mgasa-2015-0387" );
	script_tag( name: "insight", value: "Updated thunderbird packages fix security vulnerabilities: Several flaws were found in the processing of malformed web content. A web page containing malicious content could cause Thunderbird to crash or, potentially, execute arbitrary code with the privileges of the user running Thunderbird (CVE-2015-4500, CVE-2015-4509, CVE-2015-4517, CVE-2015-4521, CVE-2015-4522, CVE-2015-7174, CVE-2015-7175, CVE-2015-7176, CVE-2015-7177, CVE-2015-7180). Two information leak flaws were found in the processing of malformed web content. A web page containing malicious content could cause Thunderbird to disclose sensitive information or, in certain cases, crash (CVE-2015-4519, CVE-2015-4520)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2015-0387.html" );
	script_cve_id( "CVE-2015-4500", "CVE-2015-4509", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7180" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2015-0387" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~38.3.0~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "thunderbird-l10n", rpm: "thunderbird-l10n~38.3.0~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

