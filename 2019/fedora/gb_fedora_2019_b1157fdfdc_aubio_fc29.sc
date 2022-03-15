if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876664" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2018-19800", "CVE-2018-19801", "CVE-2018-19802", "CVE-2019-1010224", "CVE-2019-1010223", "CVE-2019-1010222" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-26 13:15:00 +0000 (Fri, 26 Jul 2019)" );
	script_tag( name: "creation_date", value: "2019-08-12 02:26:07 +0000 (Mon, 12 Aug 2019)" );
	script_name( "Fedora Update for aubio FEDORA-2019-b1157fdfdc" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC29" );
	script_xref( name: "FEDORA", value: "2019-b1157fdfdc" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OHIRMWW4JQ6UHJK4AVBJLFRLE2TPKC2W" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'aubio'
  package(s) announced via the FEDORA-2019-b1157fdfdc advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "aubio is a library for audio labeling. Its features include
segmenting a sound file before each of its attacks, performing pitch
detection, tapping the beat and producing midi streams from live
audio. The name aubio comes from &#39, audio&#39, with a typo: several
transcription errors are likely to be found in the results too.

The aim of this project is to provide these automatic labeling
features to other audio software. Functions can be used offline in
sound editors and software samplers, or online in audio effects and
virtual instruments." );
	script_tag( name: "affected", value: "'aubio' package(s) on Fedora 29." );
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
	if(!isnull( res = isrpmvuln( pkg: "aubio", rpm: "aubio~0.4.9~1.fc29", rls: "FC29" ) )){
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

