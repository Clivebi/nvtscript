if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818420" );
	script_version( "2021-09-22T08:01:20+0000" );
	script_cve_id( "CVE-2021-30565", "CVE-2021-30566", "CVE-2021-30567", "CVE-2021-30568", "CVE-2021-30569", "CVE-2021-30571", "CVE-2021-30572", "CVE-2021-30573", "CVE-2021-30574", "CVE-2021-30575", "CVE-2021-30576", "CVE-2021-30577", "CVE-2021-30578", "CVE-2021-30579", "CVE-2021-30580", "CVE-2021-30581", "CVE-2021-30582", "CVE-2021-30583", "CVE-2021-30584", "CVE-2021-30585", "CVE-2021-30586", "CVE-2021-30587", "CVE-2021-30588", "CVE-2021-30589", "CVE-2021-30590", "CVE-2021-30591", "CVE-2021-30592", "CVE-2021-30593", "CVE-2021-30594", "CVE-2021-30596", "CVE-2021-30597", "CVE-2021-30598", "CVE-2021-30599", "CVE-2021-30600", "CVE-2021-30601", "CVE-2021-30602", "CVE-2021-30603", "CVE-2021-30604", "CVE-2021-30606", "CVE-2021-30607", "CVE-2021-30608", "CVE-2021-30609", "CVE-2021-30610", "CVE-2021-30611", "CVE-2021-30612", "CVE-2021-30613", "CVE-2021-30614", "CVE-2021-30615", "CVE-2021-30616", "CVE-2021-30617", "CVE-2021-30618", "CVE-2021-30619", "CVE-2021-30620", "CVE-2021-30621", "CVE-2021-30622", "CVE-2021-30623", "CVE-2021-30624" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-22 08:01:20 +0000 (Wed, 22 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-08-11 16:16:00 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-09-15 01:13:01 +0000 (Wed, 15 Sep 2021)" );
	script_name( "Fedora: Security Advisory for chromium (FEDORA-2021-6225d60814)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-6225d60814" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QW4R2K5HVJ4R6XDZYOJCCFPIN2XHNS3L" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2021-6225d60814 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium is an open-source web browser, powered by WebKit (Blink)." );
	script_tag( name: "affected", value: "'chromium' package(s) on Fedora 34." );
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
if(release == "FC34"){
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~93.0.4577.63~1.fc34", rls: "FC34" ) )){
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

