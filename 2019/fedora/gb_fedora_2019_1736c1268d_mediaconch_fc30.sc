if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876412" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-11372", "CVE-2019-11373" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-25 06:29:00 +0000 (Sat, 25 May 2019)" );
	script_tag( name: "creation_date", value: "2019-05-26 02:12:10 +0000 (Sun, 26 May 2019)" );
	script_name( "Fedora Update for mediaconch FEDORA-2019-1736c1268d" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-1736c1268d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XGNI5HO2FHWFBTNWS3WM5MP3JHTSKGTK" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mediaconch'
  package(s) announced via the FEDORA-2019-1736c1268d advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MediaConch is an implementation checker, policy checker, reporter,
and fixer that targets preservation-level audiovisual files
(specifically Matroska, Linear Pulse Code Modulation (LPCM)
and FF Video Codec 1 (FFV1)).

This project is maintained by MediaArea and funded by PREFORMA.

This package includes the command line interface." );
	script_tag( name: "affected", value: "'mediaconch' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mediaconch", rpm: "mediaconch~18.03.2~7.fc30", rls: "FC30" ) )){
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
