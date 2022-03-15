if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882828" );
	script_version( "2021-05-21T06:00:13+0200" );
	script_tag( name: "last_modification", value: "2021-05-21 06:00:13 +0200 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-01-18 07:35:59 +0100 (Thu, 18 Jan 2018)" );
	script_cve_id( "CVE-2017-5715" );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-14 14:52:00 +0000 (Wed, 14 Apr 2021)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for microcode_ctl CESA-2018:0093 centos7" );
	script_tag( name: "summary", value: "Check the version of microcode_ctl" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The microcode_ctl packages provide
microcode updates for Intel and AMD processors.

This update supersedes microcode provided by Red Hat with the CVE-2017-5715
(Spectre) CPU branch injection vulnerability mitigation. (Historically,
Red Hat has provided updated microcode, developed by our microprocessor
partners, as a customer convenience.) Further testing has uncovered
problems with the microcode provided along with the Spectre mitigation
that could lead to system instabilities. As a result, Red Hat is providing
an microcode update that reverts to the last known good microcode version
dated before 03 January 2018. Red Hat strongly recommends that customers
contact their hardware provider for the latest microcode updates.

IMPORTANT: Customers using Intel Skylake-, Broadwell-, and Haswell-based
platforms must obtain and install updated microcode from their hardware
vendor immediately. The 'Spectre' mitigation requires both an updated
kernel from Red Hat and updated microcode from your hardware vendor." );
	script_tag( name: "affected", value: "microcode_ctl on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2018:0093" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-January/022710.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "microcode_ctl", rpm: "microcode_ctl~2.1~22.5.el7_4", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

