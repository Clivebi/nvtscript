if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879586" );
	script_version( "2021-08-23T09:01:09+0000" );
	script_cve_id( "CVE-2021-21206", "CVE-2021-21220", "CVE-2021-21201", "CVE-2021-21202", "CVE-2021-21203", "CVE-2021-21204", "CVE-2021-21221", "CVE-2021-21207", "CVE-2021-21208", "CVE-2021-21209", "CVE-2021-21210", "CVE-2021-21211", "CVE-2021-21212", "CVE-2021-21213", "CVE-2021-21214", "CVE-2021-21215", "CVE-2021-21216", "CVE-2021-21217", "CVE-2021-21218", "CVE-2021-21219", "CVE-2021-21205", "CVE-2021-21194", "CVE-2021-21195", "CVE-2021-21196", "CVE-2021-21197", "CVE-2021-21198", "CVE-2021-21199", "CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225", "CVE-2021-21226", "CVE-2021-21227", "CVE-2021-21232", "CVE-2021-21233", "CVE-2021-21228", "CVE-2021-21229", "CVE-2021-21230", "CVE-2021-21231" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 09:01:09 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-03 14:27:00 +0000 (Thu, 03 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-05-13 03:31:56 +0000 (Thu, 13 May 2021)" );
	script_name( "Fedora: Security Advisory for chromium (FEDORA-2021-c3754414e7)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC34" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-c3754414e7" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VUZBGKGVZADNA3I24NVG7HAYYUTOSN5A" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2021-c3754414e7 advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~90.0.4430.93~1.fc34", rls: "FC34" ) )){
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

