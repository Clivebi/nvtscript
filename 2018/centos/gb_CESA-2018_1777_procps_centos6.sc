if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882908" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-06-02 05:49:30 +0200 (Sat, 02 Jun 2018)" );
	script_cve_id( "CVE-2018-1124", "CVE-2018-1126" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-30 13:15:00 +0000 (Tue, 30 Jul 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for procps CESA-2018:1777 centos6" );
	script_tag( name: "summary", value: "Check the version of procps" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The procps packages contain a set of system
  utilities that provide system information. The procps packages include the
  following utilities: ps, free, skill, pkill, pgrep, snice, tload, top, uptime,
  vmstat, w, watch, pwdx, sysctl, pmap, and slabtop.

Security Fix(es):

  * procps-ng, procps: Integer overflows leading to heap overflow in
file2strvec (CVE-2018-1124)

  * procps-ng, procps: incorrect integer size in proc/alloc.* leading to
truncation / integer overflow issues (CVE-2018-1126)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section." );
	script_tag( name: "affected", value: "procps on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:1777" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-June/022911.html" );
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
	if(( res = isrpmvuln( pkg: "procps", rpm: "procps~3.2.8~45.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "procps-devel", rpm: "procps-devel~3.2.8~45.el6_9.3", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

