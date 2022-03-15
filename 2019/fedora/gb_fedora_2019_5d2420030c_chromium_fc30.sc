if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876786" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-5850", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5853", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5858", "CVE-2019-5859", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5864", "CVE-2019-5865", "CVE-2019-5848", "CVE-2019-5847" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-26 14:02:00 +0000 (Tue, 26 Nov 2019)" );
	script_tag( name: "creation_date", value: "2019-09-10 02:20:55 +0000 (Tue, 10 Sep 2019)" );
	script_name( "Fedora Update for chromium FEDORA-2019-5d2420030c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-5d2420030c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NZUE6F7GGJ3JWTTKB3XYCZ4Y4QPQXZ3P" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2019-5d2420030c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium is an open-source web browser, powered by WebKit (Blink)." );
	script_tag( name: "affected", value: "'chromium' package(s) on Fedora 30." );
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
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~76.0.3809.132~2.fc30", rls: "FC30" ) )){
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

