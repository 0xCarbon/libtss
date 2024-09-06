import ZeroxTSS from '@0xcarbon/rn-tss-module/js/NativeTss';

const getSession = (party_index: number) => ({
  parameters: { threshold: 2, share_count: 2 },
  session_id: [155, 91, 34, 177, 234, 249, 164, 92, 254, 10, 140, 65, 30,
      135, 113, 112, 137, 57, 36, 209, 201, 197, 182, 252, 49, 111, 29, 209,
      53, 68, 140, 219
  ],
  party_index,
});

const dkgPhase1 = async (parties) => {
  return await Promise.all(
    parties.map(async (session) => {
        const { fragments } = JSON.parse(
            await ZeroxTSS?.DKLsDkgPhase1(JSON.stringify({ session }))
        );

        return { fragments };
    })
  );
};

export async function dkg(): Promise<string> {
  const parties = [getSession(1), getSession(2)];
  const phase1Out = await dkgPhase1(parties);
  return JSON.stringify({
      'party 1': phase1Out[0],
      'party 2': phase1Out[1],
  }, null, 2);
}
