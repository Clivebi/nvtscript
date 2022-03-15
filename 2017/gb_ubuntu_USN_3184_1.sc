if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843030" );
	script_version( "2021-09-09T08:35:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:35:31 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-03 12:11:07 +0530 (Fri, 03 Feb 2017)" );
	script_cve_id( "CVE-2016-7553", "CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5195", "CVE-2017-5196", "CVE-2017-5356" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 00:26:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for irssi USN-3184-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'irssi'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Irssi buf.pl script set incorrect permissions. A
local attacker could use this issue to retrieve another user's window
contents. (CVE-2016-7553)

Joseph Bisch discovered that Irssi incorrectly handled comparing nicks. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5193)

It was discovered that Irssi incorrectly handled invalid nick messages. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5194)

Joseph Bisch discovered that Irssi incorrectly handled certain incomplete
control codes. A remote attacker could use this issue to cause Irssi to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2017-5195)

Hanno B&#246 ck and Joseph Bisch discovered that Irssi incorrectly handled
certain incomplete character sequences. A remote attacker could use this
issue to cause Irssi to crash, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-5196)

Hanno B&#246 ck discovered that Irssi incorrectly handled certain format
strings. A remote attacker could use this issue to cause Irssi to crash,
resulting in a denial of service. (CVE-2017-5356)" );
	script_tag( name: "affected", value: "irssi on Ubuntu 16.10,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3184-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3184-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|16\\.10|12\\.04 LTS|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.15-5ubuntu3.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.10"){
	if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.19-1ubuntu2.1", rls: "UBUNTU16.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.15-4ubuntu3.1", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "irssi", ver: "0.8.19-1ubuntu1.3", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

