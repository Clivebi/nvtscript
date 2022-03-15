if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875626" );
	script_version( "2021-09-01T14:01:32+0000" );
	script_cve_id( "CVE-2019-5754", "CVE-2019-5782", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5761", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5771", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5784", "CVE-2019-5786", "CVE-2019-5787", "CVE-2019-5788", "CVE-2019-5789", "CVE-2019-5790", "CVE-2019-5791", "CVE-2019-5792", "CVE-2019-5793", "CVE-2019-5794", "CVE-2019-5795", "CVE-2019-5796", "CVE-2019-5797", "CVE-2019-5798", "CVE-2019-5799", "CVE-2019-5800", "CVE-2019-5802", "CVE-2019-5803", "CVE-2019-5804", "CVE-2019-5801" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 14:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:12:35 +0000 (Tue, 07 May 2019)" );
	script_name( "Fedora Update for chromium FEDORA-2019-561eae4626" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-561eae4626" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZQOP53LXXPRGD4N5OBKGQTSMFXT32LF6" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2019-561eae4626 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Chromium is an open-source web browser, powered by WebKit (Blink)." );
	script_tag( name: "affected", value: "'chromium' package(s) on Fedora 29." );
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
if(release == "FC29"){
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~73.0.3683.75~2.fc29", rls: "FC29" ) )){
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

