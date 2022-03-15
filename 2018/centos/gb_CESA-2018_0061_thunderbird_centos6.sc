if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882826" );
	script_version( "2021-05-21T08:11:46+0000" );
	script_tag( name: "last_modification", value: "2021-05-21 08:11:46 +0000 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-09 10:10:25 +0100 (Tue, 09 Jan 2018)" );
	script_cve_id( "CVE-2017-7829", "CVE-2017-7846", "CVE-2017-7847", "CVE-2017-7848" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-07 12:35:00 +0000 (Tue, 07 Aug 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for thunderbird CESA-2018:0061 centos6" );
	script_tag( name: "summary", value: "Check the version of thunderbird" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail
and newsgroup client.

This update upgrades Thunderbird to version 52.5.2.

Security Fix(es):

  * Multiple flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash or,
potentially, execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2017-7846, CVE-2017-7847, CVE-2017-7848, CVE-2017-7829)

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges cure53 and Sabri Haddouche as the original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2018:0061" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-January/022706.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~52.5.2~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

