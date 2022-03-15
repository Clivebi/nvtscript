if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879840" );
	script_version( "2021-08-23T14:00:58+0000" );
	script_cve_id( "CVE-2021-30506", "CVE-2021-30507", "CVE-2021-30508", "CVE-2021-30509", "CVE-2021-30510", "CVE-2021-30511", "CVE-2021-30512", "CVE-2021-30513", "CVE-2021-30514", "CVE-2021-30515", "CVE-2021-30516", "CVE-2021-30517", "CVE-2021-30518", "CVE-2021-30519", "CVE-2021-30520", "CVE-2021-30521", "CVE-2021-30522", "CVE-2021-30523", "CVE-2021-30524", "CVE-2021-30525", "CVE-2021-30526", "CVE-2021-30527", "CVE-2021-30528", "CVE-2021-30529", "CVE-2021-30530", "CVE-2021-30531", "CVE-2021-30532", "CVE-2021-30533", "CVE-2021-30534", "CVE-2021-30535", "CVE-2021-30536", "CVE-2021-30537", "CVE-2021-30538", "CVE-2021-30539", "CVE-2021-30540", "CVE-2021-30544", "CVE-2021-30545", "CVE-2021-30546", "CVE-2021-30547", "CVE-2021-30548", "CVE-2021-30549", "CVE-2021-30550", "CVE-2021-30551", "CVE-2021-30552", "CVE-2021-30553", "CVE-2021-30554", "CVE-2021-30555", "CVE-2021-30556", "CVE-2021-30557" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-23 14:00:58 +0000 (Mon, 23 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-07-18 03:21:29 +0000 (Sun, 18 Jul 2021)" );
	script_name( "Fedora: Security Advisory for chromium (FEDORA-2021-ca58c57bdf)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-ca58c57bdf" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ETMZL6IHCTCTREEL434BQ4THQ7EOHJ43" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2021-ca58c57bdf advisory." );
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
	if(!isnull( res = isrpmvuln( pkg: "chromium", rpm: "chromium~91.0.4472.114~2.fc33", rls: "FC33" ) )){
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

