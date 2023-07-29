typedef struct _Measure {
  UINT64 start;
  UINT64 cycles;
} Measure;


VOID
MeasureStart (
    Measure  *m
    )
{
  UINT32 lowData;
  UINT32 hiData;
  __asm__ __volatile__ ("mfence;rdtsc": "=a"(lowData), "=d"(hiData) :: "memory");
  m->start = (((UINT64)hiData)<<32) | lowData;
}


VOID
MeasureEnd (
    Measure  *m
    )
{
  UINT32 lowData;
  UINT32 hiData;
  __asm__ __volatile__ ("mfence;rdtsc": "=a"(lowData), "=d"(hiData) :: "memory");
  m->cycles = (((UINT64)hiData)<<32) | lowData;
  m->cycles -= m->start;
}
