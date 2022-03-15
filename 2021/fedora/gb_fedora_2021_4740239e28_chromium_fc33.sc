if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879320" );
	script_version( "2021-08-20T12:01:13+0000" );
	script_cve_id( "CVE-2021-21162", "CVE-2021-21180", "CVE-2021-21164", "CVE-2021-21170", "CVE-2021-21181", "CVE-2021-21166", "CVE-2021-21160", "CVE-2021-21179", "CVE-2021-21187", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21183", "CVE-2021-21161", "CVE-2021-21171", "CVE-2021-21178", "CVE-2021-21169", "CVE-2021-21163", "CVE-2021-21175", "CVE-2021-21177", "CVE-2021-21185", "CVE-2021-21190", "CVE-2021-21184", "CVE-2021-21168", "CVE-2021-21167", "CVE-2021-21188", "CVE-2021-21172", "CVE-2021-21182", "CVE-2021-21176", "CVE-2021-21159", "CVE-2021-21186", "CVE-2021-21165", "CVE-2021-21189" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-20 12:01:13 +0000 (Fri, 20 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)" );
	script_tag( name: "creation_date", value: "2021-04-02 03:05:35 +0000 (Fri, 02 Apr 2021)" );
	script_name( "Fedora: Security Advisory for chromium (FEDORA-2021-4740239e28)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-4740239e28" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BBT54RKAE5XLMWSHLVUKJ7T2XHHYMXLH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2021-4740239e28 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium is an open-source web browser, powered by WebKit (Blink)." );
	script_tag( name: "affected", value: "'chromium' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~89.0.4389.90~3.fc33", rls: "FC33" ) )){
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

