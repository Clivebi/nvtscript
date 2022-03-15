if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882820" );
	script_version( "2021-05-21T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-21 06:00:13 +0200 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-05 23:54:45 +0100 (Fri, 05 Jan 2018)" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for microcode_ctl CESA-2018:0013 centos6" );
	script_tag( name: "summary", value: "Check the version of microcode_ctl" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The microcode_ctl packages provide microcode
updates for Intel and AMD processors.

Security Fix(es):

  * An industry-wide issue was found in the way many modern microprocessor
designs have implemented speculative execution of instructions (a commonly
used performance optimization). There are three primary variants of the
issue which differ in the way the speculative execution can be exploited.
Variant CVE-2017-5715 triggers the speculative execution by utilizing
branch target injection. It relies on the presence of a precisely-defined
instruction sequence in the privileged code as well as the fact that memory
accesses may cause allocation into the microprocessor's data cache even for
speculatively executed instructions that never actually commit (retire). As
a result, an unprivileged attacker could use this flaw to cross the syscall
and guest/host boundaries and read privileged memory by conducting targeted
cache side-channel attacks. (CVE-2017-5715)

Note: This is the microcode counterpart of the CVE-2017-5715 kernel
mitigation.

Red Hat would like to thank Google Project Zero for reporting this issue." );
	script_tag( name: "affected", value: "microcode_ctl on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2018:0013" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-January/022700.html" );
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
	if(( res = isrpmvuln( pkg: "microcode_ctl", rpm: "microcode_ctl~1.17~25.2.el6_9", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

