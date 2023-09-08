#include <algorithm>
#include <iostream>
#include <string>
#include <limits.h>
#include <intrin.h>

typedef unsigned __int32  uint32_t;
using namespace std;

class CPUID {
    uint32_t regs[4];

public:
    explicit CPUID(unsigned funcId, unsigned subFuncId) {

        __cpuidex((int*)regs, (int)funcId, (int)subFuncId);

    }
    const uint32_t& EAX() const { return regs[0]; }
    const uint32_t& EBX() const { return regs[1]; }
    const uint32_t& ECX() const { return regs[2]; }
    const uint32_t& EDX() const { return regs[3]; }
};

class CPUInfo {
public:
    CPUInfo();
    string  model()             const { return mModelName; }


private:
    string mModelName;
};

CPUInfo::CPUInfo()
{
    for (int i = 0x80000002; i < 0x80000005; ++i) {
        CPUID cpuID(i, 0);
        mModelName += string((const char*)&cpuID.EAX(), 4);
        mModelName += string((const char*)&cpuID.EBX(), 4);
        mModelName += string((const char*)&cpuID.ECX(), 4);
        mModelName += string((const char*)&cpuID.EDX(), 4);
    }
}

int main(int argc, char* argv[])
{
    CPUInfo cinfo;

    cout << "Nombre Procesador = " << cinfo.model() << endl;

    return 0;
}