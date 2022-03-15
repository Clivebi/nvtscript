if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0412.1" );
	script_cve_id( "CVE-2015-0822", "CVE-2015-0827", "CVE-2015-0831", "CVE-2015-0835", "CVE-2015-0836" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0412-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0412-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150412-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2015:0412-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MozillaFirefox was updated to version 31.5.0 ESR to fix five security issues.

These security issues were fixed:
- CVE-2015-0836: Multiple unspecified vulnerabilities in the browser
 engine in Mozilla Firefox before 31.5 allowed remote attackers to cause
 a denial of service (memory corruption and application crash) or
 possibly execute arbitrary code via unknown vectors (bnc#917597).
- CVE-2015-0827: Heap-based buffer overflow in the mozilla::gfx::CopyRect
 function in Mozilla Firefox before 31.5 allowed remote attackers to
 obtain sensitive information from uninitialized process memory via a
 malformed SVG graphic (bnc#917597).
- CVE-2015-0835: Multiple unspecified vulnerabilities in the browser
 engine in Mozilla Firefox before 36.0 allowed remote attackers to cause
 a denial of service (memory corruption and application crash) or
 possibly execute arbitrary code via unknown vectors (bnc#917597).
- CVE-2015-0831: Use-after-free vulnerability in the
 mozilla::dom::IndexedDB::IDBObjectStore::CreateIndex function in Mozilla
 Firefox before 31.5 allowed remote attackers to execute arbitrary code
 or cause a denial of service (heap memory corruption) via crafted
 content that is improperly handled during IndexedDB index creation
 (bnc#917597).
- CVE-2015-0822: The Form Autocompletion feature in Mozilla Firefox before
 31.5 allowed remote attackers to read arbitrary files via crafted
 JavaScript code (bnc#917597)." );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Software Development Kit 12." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~31.5.0esr~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~31.5.0esr~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~31.5.0esr~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-translations", rpm: "MozillaFirefox-translations~31.5.0esr~24.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

