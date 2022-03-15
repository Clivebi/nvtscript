if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875557" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2019-5953", "CVE-2018-20483", "CVE-2018-0494" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-04-09 02:08:16 +0000 (Tue, 09 Apr 2019)" );
	script_name( "Fedora Update for wget FEDORA-2019-9f891cd83a" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-9f891cd83a" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZR6YPWTC5IWG76BB32TNYCGQQBONYLII" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'wget' package(s) announced via the FEDORA-2019-9f891cd83a advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present
  on the target host." );
	script_tag( name: "insight", value: "GNU Wget is a file retrieval utility which
  can use either the HTTP or FTP protocols. Wget features include the ability to work
  in the background while you are logged out, recursive retrieval of directories,
  file name wildcard matching, remote file timestamp storage and comparison, use of
  Rest with FTP servers and Range with HTTP servers to retrieve files over slow or
  unstable connections, support for Proxy servers, and configurability." );
	script_tag( name: "affected", value: "'wget' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "wget", rpm: "wget~1.20.3~1.fc28", rls: "FC28" ) )){
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

