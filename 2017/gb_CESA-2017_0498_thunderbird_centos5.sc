if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882681" );
	script_version( "2021-09-09T12:15:00+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 12:15:00 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-16 09:11:21 +0100 (Thu, 16 Mar 2017)" );
	script_cve_id( "CVE-2017-5398", "CVE-2017-5400", "CVE-2017-5401", "CVE-2017-5402", "CVE-2017-5404", "CVE-2017-5405", "CVE-2017-5407", "CVE-2017-5408", "CVE-2017-5410" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-01 12:05:00 +0000 (Wed, 01 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2017:0498 centos5" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail
and newsgroup client.

This update upgrades Thunderbird to version 45.8.0.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2017-5398, CVE-2017-5400, CVE-2017-5401, CVE-2017-5402,
CVE-2017-5404, CVE-2017-5407, CVE-2017-5408, CVE-2017-5410, CVE-2017-5405)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Nils, Jerri Rice, Rh0, Anton Eliasson, David
Kohlbrenner, Ivan Fratric of Google Project Zero, Anonymous, Eric Lawrence
of Chrome Security, Boris Zbarsky, Christian Holler, Honza Bambas, Jon
Coppeard, Randell Jesup, Andre Bargull, Kan-Ru Chen, and Nathan Froyd as
the original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 5" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2017:0498" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2017-March/022338.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS5" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS5"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~45.8.0~1.el5.centos", rls: "CentOS5" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

