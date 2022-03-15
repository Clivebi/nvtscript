if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.131291" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:17:54 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_name( "Mageia Linux Local Check: mgasa-2016-0161" );
	script_tag( name: "insight", value: "Updated subversion packages fix security vulnerabilities: Daniel Shahaf and James McCoy discovered that an implementation error in the authentication against the Cyrus SASL library would permit a remote user to specify a realm string which is a prefix of the expected realm string and potentially allowing a user to authenticate using the wrong realm (CVE-2016-2167). Ivan Zhakov of VisualSVN discovered a remotely triggerable denial of service vulnerability in the mod_authz_svn module during COPY or MOVE authorization check. An authenticated remote attacker could take advantage of this flaw to cause a denial of service (Subversion server crash) via COPY or MOVE requests with specially crafted header (CVE-2016-2168)." );
	script_tag( name: "solution", value: "Update the affected packages to the latest available version." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://advisories.mageia.org/MGASA-2016-0161.html" );
	script_cve_id( "CVE-2016-2167", "CVE-2016-2168" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:P/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-20 22:15:00 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/mageia_linux", "ssh/login/release",  "ssh/login/release=MAGEIA5" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "Mageia Linux Local Security Checks mgasa-2016-0161" );
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
	if(( res = isrpmvuln( pkg: "subversion", rpm: "subversion~1.8.16~1.mga5", rls: "MAGEIA5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

