if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131188" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_tag( name: "creation_date", value: "2016-01-18 07:49:20 +0200 (Mon, 18 Jan 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0022" );
	script_tag( name: "insight", value: "An information leak flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to leak portions of memory (possibly including private SSH keys) of a successfully authenticated OpenSSH client (CVE-2016-0777). A buffer overflow flaw was found in the way the OpenSSH client roaming feature was implemented. A malicious server could potentially use this flaw to execute arbitrary code on a successfully authenticated OpenSSH client if that client used certain non-default configuration options (CVE-2016-0778). The issue only affects OpenSSH clients making use of the ProxyCommand feature. This update disables the roaming feature completely." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0022.html" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0022" );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(( res = isrpmvuln( pkg: "openssh", rpm: "openssh~6.6p1~5.6.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

